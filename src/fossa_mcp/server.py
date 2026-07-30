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
from .tools import dependencies, issues, posture, projects, reports, revisions

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
        "Read-only access to FOSSA projects, revisions, dependencies, "
        "licensing issues, vulnerability issues, quality issues, and "
        "attribution reports. No tool mutates FOSSA state."
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
