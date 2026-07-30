"""Posture-related tools for the FOSSA MCP server."""

import asyncio
from typing import Any, cast
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..models import PostureInput, PostureResponse
from ..query import split_revision_locator


async def project_posture(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    top_issue_count: int = 10,
) -> PostureResponse:
    """
    Provide one high-value, model-friendly view of a project revision's
    current FOSSA issue posture.

    This is a composite MCP workflow and is the centerpiece demo tool.
    """
    validated = PostureInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        top_issue_count=top_issue_count,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    # The issue endpoints and the dependencies endpoint want different forms of
    # the same revision (see split_revision_locator): bare id under
    # scope[revision], full locator in the path. This tool calls both, so it
    # needs both.
    full_revision_locator, revision_id = split_revision_locator(
        validated.project_locator, validated.revision_locator
    )

    scope_params = [
        ("scope[type]", "project"),
        ("scope[id]", validated.project_locator),
        ("scope[revision]", revision_id),
    ]

    async def issue_category_counts() -> tuple[int, Any]:
        return await client.request_json_with_status(
            "GET", "/v2/issues/categories", params=scope_params
        )

    async def issue_list(category: str, sort: str) -> tuple[int, Any]:
        params = [
            ("category", category),
            ("status", "active"),
            *scope_params,
            ("sort", sort),
            ("page", "1"),
            ("count", str(validated.top_issue_count)),
        ]
        return await client.request_json_with_status("GET", "/v2/issues", params=params)

    async def direct_dependencies_with_issues() -> Any:
        encoded_locator = quote(full_revision_locator, safe="")
        params = [
            ("depth[]", "direct"),
            ("hasIssues[]", "hasIssues"),
            ("page", "1"),
            ("count", str(validated.top_issue_count)),
        ]
        return await client.request_json(
            "GET", f"/v2/revisions/{encoded_locator}/dependencies", params=params
        )

    # Exactly five independent upstream calls, executed concurrently.
    results = await asyncio.gather(
        issue_category_counts(),
        issue_list("vulnerability", "severity_desc"),
        issue_list("licensing", "created_at_desc"),
        issue_list("quality", "created_at_desc"),
        direct_dependencies_with_issues(),
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, BaseException):
            raise result

    counts_status, counts_body = cast("tuple[int, Any]", results[0])
    vuln_status, vuln_body = cast("tuple[int, Any]", results[1])
    licensing_status, licensing_body = cast("tuple[int, Any]", results[2])
    quality_status, quality_body = cast("tuple[int, Any]", results[3])
    deps_body = results[4]

    analysis_state = "complete"
    if 202 in (counts_status, vuln_status, licensing_status, quality_status):
        analysis_state = "in_progress"

    raw_counts = counts_body if isinstance(counts_body, dict) else {}
    issue_counts = {
        "licensing": raw_counts.get("licensing", 0),
        "vulnerability": raw_counts.get("vulnerability", 0),
        "quality": raw_counts.get("quality", 0),
    }

    top_vulnerability_issues = vuln_body.get("issues", []) if isinstance(vuln_body, dict) else []
    top_licensing_issues = (
        licensing_body.get("issues", []) if isinstance(licensing_body, dict) else []
    )
    top_quality_issues = quality_body.get("issues", []) if isinstance(quality_body, dict) else []
    direct_dependencies = deps_body.get("dependencies", []) if isinstance(deps_body, dict) else []

    return PostureResponse(
        project_locator=validated.project_locator,
        revision_locator=full_revision_locator,
        issue_counts=issue_counts,
        top_vulnerability_issues=top_vulnerability_issues,
        top_licensing_issues=top_licensing_issues,
        top_quality_issues=top_quality_issues,
        direct_dependencies_with_issues=direct_dependencies,
        analysis_state=analysis_state,
    )
