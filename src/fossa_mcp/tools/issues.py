"""Issue-related tools for the FOSSA MCP server."""

from datetime import datetime
from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import (
    ChangeStatus,
    IssueCategory,
    IssueDepth,
    IssueListInput,
    IssueSort,
    IssueStatus,
    ScopeType,
    Severity,
    SeveritySource,
)
from ..query import add_repeated, bool_to_str, split_revision_locator


async def list_issues(
    ctx: Context,
    category: IssueCategory,
    status: IssueStatus = "active",
    scope_type: ScopeType = "global",
    project_locator: str | None = None,
    revision_locator: str | None = None,
    compare_to_revision: str | None = None,
    change_status: ChangeStatus | None = None,
    issue_ids: list[int] | None = None,
    search: str | None = None,
    depths: list[IssueDepth] | None = None,
    issue_types: list[str] | None = None,
    package_managers: list[str] | None = None,
    cwes: list[str] | None = None,
    project_labels: list[str] | None = None,
    severity: list[Severity] | None = None,
    severity_source: list[SeveritySource] | None = None,
    found_before: datetime | None = None,
    found_after: datetime | None = None,
    issue_source: list[str] | None = None,
    sort: IssueSort | None = None,
    include_direct_dependency_origin_paths: bool = False,
    page: int = 1,
    count: int = 20,
) -> dict[str, Any]:
    """
    Query licensing, vulnerability, or quality issues globally or for one
    project revision. Supports comparing issues between revisions.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = IssueListInput(
        category=category,
        status=status,
        scope_type=scope_type,
        project_locator=project_locator,
        revision_locator=revision_locator,
        compare_to_revision=compare_to_revision,
        change_status=change_status,
        issue_ids=issue_ids,
        search=search,
        depths=depths,
        issue_types=issue_types,
        package_managers=package_managers,
        cwes=cwes,
        project_labels=project_labels,
        severity=severity,
        severity_source=severity_source,
        found_before=found_before,
        found_after=found_after,
        issue_source=issue_source,
        sort=sort,
        include_direct_dependency_origin_paths=include_direct_dependency_origin_paths,
        page=page,
        count=count,
    )
    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    params = _build_issue_query(validated)

    endpoint = "GET /v2/issues"
    status_code, result = await client.request_json_with_status("GET", "/v2/issues", params=params)

    if status_code == 202:
        message = result.get("message") if isinstance(result, dict) else None
        return {
            "ok": True,
            "endpoint": endpoint,
            "state": "analysis_in_progress",
            "message": message,
            "data": result,
        }

    return {"ok": True, "endpoint": endpoint, "data": result}


def _build_issue_query(validated: IssueListInput) -> list[tuple[str, str]]:
    params: list[tuple[str, str]] = [
        ("category", validated.category),
        ("status", validated.status),
        ("scope[type]", validated.scope_type),
        ("page", str(validated.page)),
        ("count", str(validated.count)),
    ]

    if validated.scope_type == "project":
        # The IssueListInput model validator guarantees these are set for
        # project scope.
        assert validated.project_locator is not None
        assert validated.revision_locator is not None
        _, revision_id = split_revision_locator(
            validated.project_locator, validated.revision_locator
        )
        params.append(("scope[id]", validated.project_locator))
        params.append(("scope[revision]", revision_id))

        if validated.compare_to_revision is not None:
            assert validated.change_status is not None
            _, compare_id = split_revision_locator(
                validated.project_locator, validated.compare_to_revision
            )
            params.append(("scope[compareTo][revision]", compare_id))
            params.append(("scope[compareTo][changeStatus]", validated.change_status))

    issue_id_strs = [str(i) for i in validated.issue_ids] if validated.issue_ids else None
    add_repeated(params, "ids", issue_id_strs)
    add_repeated(params, "filter[depths]", validated.depths)
    add_repeated(params, "filter[type]", validated.issue_types)
    add_repeated(params, "filter[packageManagers]", validated.package_managers)
    add_repeated(params, "filter[cwes]", validated.cwes)
    add_repeated(params, "filter[projectLabels]", validated.project_labels)
    add_repeated(params, "filter[severity]", validated.severity)
    add_repeated(params, "filter[severitySource]", validated.severity_source)
    add_repeated(params, "filter[issueSource]", validated.issue_source)

    if validated.search is not None:
        params.append(("filter[search]", validated.search))

    if validated.found_before is not None:
        params.append(("filter[foundBefore]", validated.found_before.isoformat()))

    if validated.found_after is not None:
        params.append(("filter[foundAfter]", validated.found_after.isoformat()))

    if validated.sort is not None:
        params.append(("sort", validated.sort))

    params.append(
        (
            "includeDirectDependencyOriginPaths",
            bool_to_str(validated.include_direct_dependency_origin_paths),
        )
    )

    return params


async def get_issue(
    ctx: Context,
    issue_id: int,
    category: IssueCategory,
    scope_type: ScopeType = "global",
    project_locator: str | None = None,
    revision_locator: str | None = None,
) -> dict[str, Any]:
    """Retrieve complete detail for one issue."""
    if issue_id < 1:
        raise ValueError("Issue ID must be >= 1")

    if scope_type == "global":
        if project_locator is not None:
            raise ValueError("project_locator must be None for global scope")
        if revision_locator is not None:
            raise ValueError("revision_locator must be None for global scope")
    else:
        if project_locator is None:
            raise ValueError("project_locator is required for project scope")
        if revision_locator is None:
            raise ValueError("revision_locator is required for project scope")

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [
        ("category", category),
        ("scope[type]", scope_type),
    ]

    if scope_type == "project":
        assert project_locator is not None
        assert revision_locator is not None
        _, revision_id = split_revision_locator(project_locator, revision_locator)
        params.append(("scope[id]", project_locator))
        params.append(("scope[revision]", revision_id))

    result = await client.request_json("GET", f"/v2/issues/{issue_id}", params=params)

    return {"ok": True, "endpoint": "GET /v2/issues/{issueId}", "data": result}
