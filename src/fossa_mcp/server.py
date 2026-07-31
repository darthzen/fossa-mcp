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
from .tools import (
    dependencies,
    issues,
    policies,
    posture,
    projects,
    release_groups,
    reports,
    revisions,
)

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
        "Access to a FOSSA organization across five domains: projects and their "
        "settings, revisions and the attribution reports built from them, "
        "dependencies, issues (licensing, vulnerability, and quality, together "
        "with the exceptions, disputes, and saved filters around them), and "
        "release groups. Security policy assignment and evaluation sit on top.\n\n"
        "Most tools only read. Every tool that changes FOSSA state says so on "
        "the second line of its description and names the environment variables "
        "it needs. Writes are tiered and off by default:\n"
        "- FOSSA_ALLOW_WRITES=true permits creates and updates.\n"
        "- FOSSA_ALLOW_DESTRUCTIVE=true, which is only effective alongside "
        "FOSSA_ALLOW_WRITES, additionally permits deletes and the bulk "
        "operations whose target set is a filter rather than an explicit list.\n"
        "A tool whose tier is disabled refuses before it constructs a request, "
        "so nothing reaches FOSSA.\n\n"
        "Read before you write. The destructive tools act on sets the caller "
        "cannot see from the arguments alone, and FOSSA has no undo: run "
        "fossa_list_issues before fossa_update_issues, fossa_get_issue_exceptions "
        "before fossa_delete_issue_exceptions, fossa_list_projects before "
        "fossa_delete_projects, and fossa_evaluate_security_policy before "
        "fossa_enable_security_policy, passing the same arguments each time.\n\n"
        "Release groups are addressed by numeric id only; there is no "
        "list-release-groups endpoint, so find the id in the release group's "
        "FOSSA URL or through fossa_get_project_associations."
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

# A write that converges. These set named fields on a named target (PUT/PATCH,
# or a PUT over an explicit list of locators): re-applying the same call leaves
# FOSSA in the state the first call produced, so idempotentHint is True and a
# client may retry a timeout. Nothing is removed and no target set is implied
# by a filter, so destructiveHint is False.
_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

# Security policy assignment has exactly the profile above — re-applying the
# same policy id converges rather than destroying anything — and keeps its own
# name because DECISIONS.md §5 addresses these two tools specifically.
_POLICY_WRITE = _WRITE

# A write that accumulates. POSTs that mint a record, queue a background job,
# send mail, or regenerate a URL: the second call is a second dispute, a second
# export job, a second email — not a no-op — so idempotentHint is False and a
# client must not retry blindly. They still remove nothing, so destructiveHint
# stays False even where the effect is externally visible.
_WRITE_ACCUMULATING = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

# Deletes, and only deletes. destructiveHint is reserved for these and for the
# unbounded-target case below, so that a client treating the hint as a
# confirmation prompt is prompted where FOSSA offers no undo. Repeating a
# delete removes nothing further, so idempotentHint is True.
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

# The unbounded-target case: fossa_update_issues picks its write tier at call
# time, acting on named issue_ids (WRITE) or on everything matching the filters
# (DESTRUCTIVE, per DECISIONS.md §7). A static annotation has to advertise the
# worse of the two, so destructiveHint is True. idempotentHint is False because
# the issueException action creates a durable ignore rule, and creating it twice
# is not the same as creating it once.
_DESTRUCTIVE_UNBOUNDED = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

# --- projects ----------------------------------------------------------------
mcp.tool(name="fossa_list_projects", annotations=_READ_ONLY)(projects.list_projects)
mcp.tool(name="fossa_get_project", annotations=_READ_ONLY)(projects.get_project)
mcp.tool(name="fossa_get_projects_summary", annotations=_READ_ONLY)(projects.get_projects_summary)
mcp.tool(name="fossa_get_project_associations", annotations=_READ_ONLY)(
    projects.get_project_associations
)
mcp.tool(name="fossa_export_project_issues", annotations=_READ_ONLY)(projects.export_project_issues)
mcp.tool(name="fossa_update_project", annotations=_WRITE)(projects.update_project)
mcp.tool(name="fossa_apply_project_label", annotations=_WRITE)(projects.apply_project_label)
# Regenerating the slug mints a new one and breaks every previously shared
# report link, so it is not idempotent. It is still not destructiveHint=True:
# that hint is kept for deletes and unbounded targets, and the link breakage is
# spelled out in the tool's own description.
mcp.tool(name="fossa_generate_project_attribution_slug", annotations=_WRITE_ACCUMULATING)(
    projects.generate_project_attribution_slug
)
mcp.tool(name="fossa_delete_project_attribution_slug", annotations=_DESTRUCTIVE)(
    projects.delete_project_attribution_slug
)
mcp.tool(name="fossa_delete_project", annotations=_DESTRUCTIVE)(projects.delete_project)
mcp.tool(name="fossa_delete_projects", annotations=_DESTRUCTIVE)(projects.delete_projects)

# --- revisions ---------------------------------------------------------------
mcp.tool(name="fossa_list_project_revisions", annotations=_READ_ONLY)(
    revisions.list_project_revisions
)
mcp.tool(name="fossa_list_revision_scans", annotations=_READ_ONLY)(revisions.list_revision_scans)
mcp.tool(name="fossa_get_revision_notice_files", annotations=_READ_ONLY)(
    revisions.get_revision_notice_files
)
mcp.tool(name="fossa_get_revision_sbom", annotations=_READ_ONLY)(revisions.get_revision_sbom)
mcp.tool(name="fossa_get_revision_remediation_guidance", annotations=_READ_ONLY)(
    revisions.get_revision_remediation_guidance
)
mcp.tool(name="fossa_get_revision_attribution_json", annotations=_READ_ONLY)(
    revisions.get_revision_attribution_json
)
mcp.tool(name="fossa_render_revision_attribution", annotations=_READ_ONLY)(
    revisions.render_revision_attribution
)
mcp.tool(name="fossa_list_revision_dependencies_v1", annotations=_READ_ONLY)(
    revisions.list_revision_dependencies_v1
)
mcp.tool(name="fossa_update_revision", annotations=_WRITE)(revisions.update_revision)
# Two GETs that are writes in effect: one queues an outbound email, the other
# publishes an unauthenticated URL onto the dependency inventory. Each call has
# a fresh external effect, so neither is idempotent.
mcp.tool(name="fossa_email_revision_attribution", annotations=_WRITE_ACCUMULATING)(
    revisions.email_revision_attribution
)
mcp.tool(name="fossa_create_public_attribution_report", annotations=_WRITE_ACCUMULATING)(
    revisions.create_public_attribution_report
)

# --- dependencies ------------------------------------------------------------
mcp.tool(name="fossa_list_dependencies", annotations=_READ_ONLY)(dependencies.list_dependencies)
mcp.tool(name="fossa_get_dependency", annotations=_READ_ONLY)(dependencies.get_dependency)

# --- issues, issue overview, and saved issue filters -------------------------
mcp.tool(name="fossa_list_issues", annotations=_READ_ONLY)(issues.list_issues)
mcp.tool(name="fossa_get_issue", annotations=_READ_ONLY)(issues.get_issue)
mcp.tool(name="fossa_get_issue_facets", annotations=_READ_ONLY)(issues.get_issue_facets)
mcp.tool(name="fossa_list_issue_revisions", annotations=_READ_ONLY)(issues.list_issue_revisions)
mcp.tool(name="fossa_compare_issue_summaries", annotations=_READ_ONLY)(
    issues.compare_issue_summaries
)
mcp.tool(name="fossa_get_issue_affected_projects", annotations=_READ_ONLY)(
    issues.get_issue_affected_projects
)
mcp.tool(name="fossa_export_global_issues_csv", annotations=_READ_ONLY)(
    issues.export_global_issues_csv
)
mcp.tool(name="fossa_get_issue_exceptions", annotations=_READ_ONLY)(issues.get_issue_exceptions)
mcp.tool(name="fossa_get_issue_overview", annotations=_READ_ONLY)(issues.get_issue_overview)
mcp.tool(name="fossa_get_issue_filters", annotations=_READ_ONLY)(issues.get_issue_filters)
mcp.tool(name="fossa_update_issues", annotations=_DESTRUCTIVE_UNBOUNDED)(issues.update_issues)
mcp.tool(name="fossa_extend_issue_exception", annotations=_WRITE)(issues.extend_issue_exception)
mcp.tool(name="fossa_delete_issue_exceptions", annotations=_DESTRUCTIVE)(
    issues.delete_issue_exceptions
)
mcp.tool(name="fossa_create_issue_dispute", annotations=_WRITE_ACCUMULATING)(
    issues.create_issue_dispute
)
# Reads nothing back: it queues a background export job in the organization and
# returns a token, so a retry is a second job.
mcp.tool(name="fossa_export_issue_overview", annotations=_WRITE_ACCUMULATING)(
    issues.export_issue_overview
)
# Create-or-update behind one tool: without filter_id it POSTs a new saved
# filter every time, so the annotation follows the create branch.
mcp.tool(name="fossa_save_issue_filter", annotations=_WRITE_ACCUMULATING)(issues.save_issue_filter)
mcp.tool(name="fossa_delete_issue_filter", annotations=_DESTRUCTIVE)(issues.delete_issue_filter)

# --- release groups ----------------------------------------------------------
mcp.tool(name="fossa_get_release_group", annotations=_READ_ONLY)(release_groups.get_release_group)
mcp.tool(name="fossa_list_release_group_releases", annotations=_READ_ONLY)(
    release_groups.list_release_group_releases
)
mcp.tool(name="fossa_get_release_group_release", annotations=_READ_ONLY)(
    release_groups.get_release_group_release
)
mcp.tool(name="fossa_get_release_group_attribution_report", annotations=_READ_ONLY)(
    release_groups.get_release_group_attribution_report
)
mcp.tool(name="fossa_get_release_group_attribution_status", annotations=_READ_ONLY)(
    release_groups.get_release_group_attribution_status
)
mcp.tool(name="fossa_create_release_group", annotations=_WRITE_ACCUMULATING)(
    release_groups.create_release_group
)
mcp.tool(name="fossa_update_release_group", annotations=_WRITE)(release_groups.update_release_group)
mcp.tool(name="fossa_delete_release_group", annotations=_DESTRUCTIVE)(
    release_groups.delete_release_group
)
mcp.tool(name="fossa_create_release_group_release", annotations=_WRITE_ACCUMULATING)(
    release_groups.create_release_group_release
)
mcp.tool(name="fossa_update_release_group_release", annotations=_WRITE)(
    release_groups.update_release_group_release
)
mcp.tool(name="fossa_delete_release_group_release", annotations=_DESTRUCTIVE)(
    release_groups.delete_release_group_release
)
# Queues a job and, with is_publishing set, pushes the report onto the SBOM
# portal. The synchronous v2 read is fossa_get_release_group_attribution_report.
mcp.tool(name="fossa_queue_release_group_attribution_report", annotations=_WRITE_ACCUMULATING)(
    release_groups.queue_release_group_attribution_report
)

# --- posture and reports -----------------------------------------------------
mcp.tool(name="fossa_project_posture", annotations=_READ_ONLY)(posture.project_posture)
mcp.tool(name="fossa_get_attribution_report", annotations=_READ_ONLY)(
    reports.get_attribution_report
)

# --- security policy ---------------------------------------------------------
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
