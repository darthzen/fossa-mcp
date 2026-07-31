"""FOSSA MCP server implementation."""

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from . import __version__
from .client import FossaClient
from .config import Settings
from .tools import dependencies, issues, policies, posture, projects, reports, revisions

logger = logging.getLogger(__name__)

settings = Settings()


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Own the single FOSSA HTTP client for the life of the server process."""
    client = FossaClient(settings)
    try:
        yield {"client": client, "settings": settings}
    finally:
        await client.aclose()


mcp = FastMCP(
    "FOSSA",
    instructions=(
        "Access to FOSSA projects, revisions, dependencies, licensing issues, "
        "vulnerability issues, quality issues, attribution reports, and "
        "security policy enforcement.\n\n"
        "Every tool is read-only except the two security policy tools "
        "(fossa_enable_security_policy, fossa_assign_security_policy_to_projects), "
        "which change what FOSSA enforces for a project and are refused unless "
        "the operator set FOSSA_ALLOW_WRITES=true. Prefer "
        "fossa_evaluate_security_policy to see what a policy would block before "
        "enabling anything."
    ),
    lifespan=lifespan,
    host=settings.fossa_http_host,
    port=settings.fossa_http_port,
)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    """Liveness endpoint for the streamable-http transport."""
    return PlainTextResponse("ok")


_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=True)

# Policy writes are idempotent assignments, not deletions: re-applying the same
# policy id converges rather than destroying anything, so destructiveHint is
# False. They are emphatically not read-only, and idempotentHint is what tells a
# client a retry is safe.
_POLICY_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

mcp.tool(name="fossa_list_projects", annotations=_READ_ONLY)(projects.list_projects)
mcp.tool(name="fossa_get_project", annotations=_READ_ONLY)(projects.get_project)
mcp.tool(name="fossa_list_project_revisions", annotations=_READ_ONLY)(
    revisions.list_project_revisions
)
mcp.tool(name="fossa_list_dependencies", annotations=_READ_ONLY)(dependencies.list_dependencies)
mcp.tool(name="fossa_get_dependency", annotations=_READ_ONLY)(dependencies.get_dependency)
mcp.tool(name="fossa_list_issues", annotations=_READ_ONLY)(issues.list_issues)
mcp.tool(name="fossa_get_issue", annotations=_READ_ONLY)(issues.get_issue)
mcp.tool(name="fossa_project_posture", annotations=_READ_ONLY)(posture.project_posture)
mcp.tool(name="fossa_get_attribution_report", annotations=_READ_ONLY)(
    reports.get_attribution_report
)
mcp.tool(name="fossa_get_security_policy", annotations=_READ_ONLY)(policies.get_security_policy)
mcp.tool(name="fossa_evaluate_security_policy", annotations=_READ_ONLY)(
    policies.evaluate_security_policy
)
mcp.tool(name="fossa_enable_security_policy", annotations=_POLICY_WRITE)(
    policies.enable_security_policy
)
mcp.tool(name="fossa_assign_security_policy_to_projects", annotations=_POLICY_WRITE)(
    policies.assign_security_policy_to_projects
)


def _forbid_unexpected_tool_arguments(server: FastMCP) -> None:
    """Make tools reject unknown arguments instead of silently dropping them.

    FastMCP 1.28 generates each tool's argument model with Pydantic's default
    `extra="ignore"`, so a client that passes a misspelled or invented argument
    gets a successful call with that argument discarded — an easy way for a
    model to believe it applied a filter that never reached FOSSA. Tighten every
    generated model and republish its JSON schema so `additionalProperties:
    false` is advertised too.

    This reaches into the tool manager because 1.28 exposes no public hook. Fold
    it into tool registration when moving to the 2.x SDK (see DECISIONS.md).
    """
    for tool in server._tool_manager._tools.values():
        arg_model = tool.fn_metadata.arg_model
        arg_model.model_config["extra"] = "forbid"
        arg_model.model_rebuild(force=True)
        tool.parameters = arg_model.model_json_schema(by_alias=True)


_forbid_unexpected_tool_arguments(mcp)

_ALLOWED_TRANSPORTS = ("stdio", "streamable-http")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for the FOSSA MCP server."""
    args = sys.argv[1:] if argv is None else argv
    transport = "stdio"

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--transport":
            if idx + 1 >= len(args):
                raise ValueError("Missing transport value after --transport")
            transport = args[idx + 1]
            if transport not in _ALLOWED_TRANSPORTS:
                raise ValueError(f"Unknown transport: {transport}")
            idx += 2
        elif arg == "--version":
            print(f"fossa-mcp version {__version__}")
            return
        else:
            raise ValueError(f"Unknown argument: {arg}")

    logging.basicConfig(
        level=settings.log_level_int,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    logger.info("Starting FOSSA MCP server with transport: %s", transport)

    # mcp.run() is synchronous: it drives its own anyio event loop.
    mcp.run(transport=transport)
