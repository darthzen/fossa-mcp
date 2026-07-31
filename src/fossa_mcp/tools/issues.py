"""Issue-related tools for the FOSSA MCP server.

Covers the `/v2/issues` family, the issue overview counts under
`/issue_counts`, and the organization's saved issue filters under
`/issue-filters`.

Two things about this domain are worth stating up front:

* **Bulk updates are tiered by blast radius, not by verb.** `PUT /v2/issues`
  applies one action either to a list of issue ids or to everything matching
  the current filters. The first is `WRITE`; the second is `DESTRUCTIVE`,
  because the caller cannot see the target set before it acts. The same rule
  puts every exception delete at `DESTRUCTIVE`.
* **Only the `global` and `project` scopes are exposed.** FOSSA also accepts
  `scope[type]=releaseGroup` on most of these endpoints. Release groups are a
  separate domain with their own locator model, so they are left out here
  rather than half-supported.
"""

import json
from datetime import date, datetime
from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..errors import FossaApiError
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
from ..models.issues import (
    DisputeReason,
    ExceptionDeleteCategory,
    ExceptionSortBy,
    IgnoreReason,
    IgnoreScope,
    IssueAffectedProjectsInput,
    IssueCompareSummaryInput,
    IssueCsvExportInput,
    IssueDisputeInput,
    IssueExceptionDeleteInput,
    IssueExceptionExtendInput,
    IssueExceptionReadInput,
    IssueFacet,
    IssueFacetInput,
    IssueFilterDeleteInput,
    IssueFilterGroup,
    IssueFilterReadInput,
    IssueFilterSaveInput,
    IssueFilterSort,
    IssueOverviewInput,
    IssueRevisionListInput,
    IssueRevisionSort,
    IssueUpdateAction,
    IssueUpdateInput,
    PackageScope,
    SortOrder,
)
from ..query import add_repeated, bool_to_str, split_revision_locator
from ..writes import WriteTier, require_tier


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


# --- shared helpers ----------------------------------------------------------

_FACET_PATHS: dict[str, str] = {
    "categories": "/v2/issues/categories",
    "cwes": "/v2/issues/cwes",
    "license-list": "/v2/issues/license-list",
    "package-managers": "/v2/issues/package-managers",
    "statuses": "/v2/issues/statuses",
    "types": "/v2/issues/types",
}


def _scope_params(
    scope_type: ScopeType,
    project_locator: str | None,
    revision_locator: str | None,
) -> list[tuple[str, str]]:
    """Build the `scope[...]` query pairs the issue endpoints expect."""
    params: list[tuple[str, str]] = [("scope[type]", scope_type)]
    if scope_type == "project":
        # Every caller validates its scope through an input model first.
        assert project_locator is not None
        assert revision_locator is not None
        _, revision_id = split_revision_locator(project_locator, revision_locator)
        params.append(("scope[id]", project_locator))
        params.append(("scope[revision]", revision_id))
    return params


def _add_plain_repeated(
    params: list[tuple[str, str]],
    key: str,
    values: list[str] | None,
) -> None:
    """Repeat a query key without the `[]` suffix, which `teamId` needs."""
    for value in values or []:
        params.append((key, value))


async def _request_tolerating_empty_body(
    client: FossaClient,
    method: str,
    path: str,
    *,
    params: list[tuple[str, str]] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any] | list[Any] | None:
    """Call FOSSA where a successful response may carry no body.

    `PUT /v2/issues/exceptions/{id}` answers `204`, and `DELETE
    /issue-filters/{id}` documents a `200` with no content. `request_json`
    reports an unparseable body as a `FossaApiError` regardless of status, so
    translate that back into a success with no data when the status was in the
    2xx range. Anything else propagates unchanged.
    """
    try:
        _, body = await client.request_json_with_status(
            method, path, params=params, json_body=json_body
        )
    except FossaApiError as exc:
        if 200 <= exc.status_code < 300:
            return None
        raise
    return body


# --- issue reads -------------------------------------------------------------


async def get_issue_facets(
    ctx: Context,
    facet: IssueFacet,
    category: IssueCategory | None = None,
    status: IssueStatus | None = None,
    scope_type: ScopeType = "global",
    project_locator: str | None = None,
    revision_locator: str | None = None,
    team_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Summarize the current issue set one dimension at a time: counts by
    category, by type, or by status, or the distinct CWEs, licenses, or package
    managers that issues were found in.

    Read-only. Use this before fossa_list_issues to find out what is worth
    listing. `category` is required for the license-list, package-managers, and
    statuses facets and rejected by the others; `status` applies only to cwes
    and package-managers.
    """
    validated = IssueFacetInput(
        facet=facet,
        category=category,
        status=status,
        scope_type=scope_type,
        project_locator=project_locator,
        revision_locator=revision_locator,
        team_ids=team_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = []
    if validated.category is not None:
        params.append(("category", validated.category))
    if validated.status is not None:
        params.append(("status", validated.status))
    params.extend(
        _scope_params(validated.scope_type, validated.project_locator, validated.revision_locator)
    )
    _add_plain_repeated(params, "teamId", validated.team_ids)

    path = _FACET_PATHS[validated.facet]
    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {path}", "data": result}


async def list_issue_revisions(
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
    project_labels: list[str] | None = None,
    licenses: list[str] | None = None,
    severity: list[Severity] | None = None,
    found_after: datetime | None = None,
    sort: IssueRevisionSort | None = None,
    team_ids: list[str] | None = None,
    page: int = 1,
    count: int = 20,
) -> dict[str, Any]:
    """
    List issues grouped by the dependency revision that carries them, with per
    revision issue and project counts.

    Read-only. This is the "which packages should we upgrade first" view;
    fossa_list_issues is the per-issue view of the same data.
    """
    validated = IssueRevisionListInput(
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
        project_labels=project_labels,
        licenses=licenses,
        severity=severity,
        found_after=found_after,
        sort=sort,
        team_ids=team_ids,
        page=page,
        count=count,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    params: list[tuple[str, str]] = [
        ("category", validated.category),
        ("status", validated.status),
    ]
    params.extend(
        _scope_params(validated.scope_type, validated.project_locator, validated.revision_locator)
    )

    if validated.compare_to_revision is not None:
        assert validated.project_locator is not None
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
    add_repeated(params, "filter[projectLabels]", validated.project_labels)
    add_repeated(params, "filter[licenses]", validated.licenses)
    add_repeated(params, "filter[severity]", validated.severity)

    if validated.search is not None:
        params.append(("filter[search]", validated.search))
    if validated.found_after is not None:
        params.append(("filter[foundAfter]", validated.found_after.isoformat()))
    if validated.sort is not None:
        params.append(("sort", validated.sort))

    _add_plain_repeated(params, "teamId", validated.team_ids)
    params.append(("page", str(validated.page)))
    params.append(("count", str(validated.count)))

    result = await client.request_json("GET", "/v2/issues/revisions", params=params)

    return {"ok": True, "endpoint": "GET /v2/issues/revisions", "data": result}


async def compare_issue_summaries(
    ctx: Context,
    category: IssueCategory,
    project_locator: str,
    revision_locator: str,
    compare_to_revision: str,
    change_status: ChangeStatus | None = None,
    search: str | None = None,
    depths: list[IssueDepth] | None = None,
    issue_types: list[str] | None = None,
    package_managers: list[str] | None = None,
    cwes: list[str] | None = None,
    project_labels: list[str] | None = None,
    severity: list[Severity] | None = None,
) -> dict[str, Any]:
    """
    Count how many issues are new, remediated, or unchanged between two
    revisions of one project.

    Read-only. Answers "what did this build change" in one call; use
    fossa_list_issues with compare_to_revision to see the issues themselves.
    """
    validated = IssueCompareSummaryInput(
        category=category,
        project_locator=project_locator,
        revision_locator=revision_locator,
        compare_to_revision=compare_to_revision,
        change_status=change_status,
        search=search,
        depths=depths,
        issue_types=issue_types,
        package_managers=package_managers,
        cwes=cwes,
        project_labels=project_labels,
        severity=severity,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [("category", validated.category)]
    params.extend(_scope_params("project", validated.project_locator, validated.revision_locator))

    _, compare_id = split_revision_locator(validated.project_locator, validated.compare_to_revision)
    params.append(("scope[compareTo][revision]", compare_id))
    if validated.change_status is not None:
        params.append(("scope[compareTo][changeStatus]", validated.change_status))

    add_repeated(params, "filter[depths]", validated.depths)
    add_repeated(params, "filter[type]", validated.issue_types)
    add_repeated(params, "filter[packageManagers]", validated.package_managers)
    add_repeated(params, "filter[cwes]", validated.cwes)
    add_repeated(params, "filter[projectLabels]", validated.project_labels)
    add_repeated(params, "filter[severity]", validated.severity)

    if validated.search is not None:
        params.append(("filter[search]", validated.search))

    result = await client.request_json("GET", "/v2/issues/compare/summaries", params=params)

    return {"ok": True, "endpoint": "GET /v2/issues/compare/summaries", "data": result}


async def get_issue_affected_projects(
    ctx: Context,
    issue_id: int,
    category: IssueCategory,
    scope_type: ScopeType = "global",
    project_locator: str | None = None,
    revision_locator: str | None = None,
) -> dict[str, Any]:
    """
    List the projects and revisions affected by one issue.

    Read-only. This is the blast-radius view of a single CVE or policy
    conflict: which projects carry it, on which branch, and whether a ticket is
    already filed.
    """
    validated = IssueAffectedProjectsInput(
        issue_id=issue_id,
        category=category,
        scope_type=scope_type,
        project_locator=project_locator,
        revision_locator=revision_locator,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [("category", validated.category)]
    params.extend(
        _scope_params(validated.scope_type, validated.project_locator, validated.revision_locator)
    )

    result = await client.request_json(
        "GET", f"/v2/issues/{validated.issue_id}/affected-projects", params=params
    )

    return {
        "ok": True,
        "endpoint": "GET /v2/issues/{issueId}/affected-projects",
        "data": result,
    }


async def export_global_issues_csv(
    ctx: Context,
    email: bool = True,
    team_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Request the organization-wide issues report as CSV.

    Read-only with respect to FOSSA state. With email=true (the default) FOSSA
    queues the export and mails it to the calling token's user, and this returns
    the background task metadata. With email=false FOSSA streams a zip archive,
    which this tool reports on but does not return: the archive is binary and
    cannot travel over MCP as text.

    Requires the Create permission on OrganizationReport or TeamReport.
    """
    validated = IssueCsvExportInput(email=email, team_ids=team_ids)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [("email", bool_to_str(validated.email))]
    _add_plain_repeated(params, "teamIds", validated.team_ids)

    content, content_type = await client.request_text("GET", "/v2/issues/csv/global", params=params)

    endpoint = "GET /v2/issues/csv/global"
    if content_type is not None and "json" in content_type:
        try:
            return {"ok": True, "endpoint": endpoint, "data": json.loads(content)}
        except json.JSONDecodeError:
            pass

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {
            "content_type": content_type,
            "delivered": "stream",
            "note": (
                "FOSSA streamed the report as a zip archive rather than queueing it. "
                "Call again with email=true to have it delivered and to receive the "
                "background task metadata instead."
            ),
        },
    }


async def get_issue_exceptions(
    ctx: Context,
    exception_id: int | None = None,
    category: IssueCategory | None = None,
    project_id: str | None = None,
    release_group_id: int | None = None,
    search: str | None = None,
    sort_by: ExceptionSortBy | None = None,
    order_by: SortOrder | None = None,
    page: int = 1,
    count: int = 20,
) -> dict[str, Any]:
    """
    List the organization's issue ignore rules, or fetch one by id.

    Read-only. An exception is what keeps an issue out of the active set: it
    records the scope it applies to, who created it, and when it expires. Pass
    exception_id for a single rule, or category to list.
    """
    validated = IssueExceptionReadInput(
        exception_id=exception_id,
        category=category,
        project_id=project_id,
        release_group_id=release_group_id,
        search=search,
        sort_by=sort_by,
        order_by=order_by,
        page=page,
        count=count,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    if validated.exception_id is not None:
        result = await client.request_json("GET", f"/v2/issues/exceptions/{validated.exception_id}")
        return {"ok": True, "endpoint": "GET /v2/issues/exceptions/{id}", "data": result}

    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    assert validated.category is not None
    params: list[tuple[str, str]] = [("filters[category]", validated.category)]
    if validated.project_id is not None:
        params.append(("filters[projectId]", validated.project_id))
    if validated.release_group_id is not None:
        params.append(("filters[releaseGroupId]", str(validated.release_group_id)))
    if validated.search is not None:
        params.append(("search", validated.search))
    if validated.sort_by is not None:
        params.append(("sortBy", validated.sort_by))
    if validated.order_by is not None:
        params.append(("orderBy", validated.order_by))
    params.append(("page", str(validated.page)))
    params.append(("count", str(validated.count)))

    result = await client.request_json("GET", "/v2/issues/exceptions", params=params)

    return {"ok": True, "endpoint": "GET /v2/issues/exceptions", "data": result}


# --- issue writes ------------------------------------------------------------


async def update_issues(
    ctx: Context,
    action: IssueUpdateAction,
    category: IssueCategory,
    issue_ids: list[int] | None = None,
    status: IssueStatus = "active",
    scope_type: ScopeType = "global",
    project_locator: str | None = None,
    revision_locator: str | None = None,
    search: str | None = None,
    depths: list[IssueDepth] | None = None,
    issue_types: list[str] | None = None,
    package_managers: list[str] | None = None,
    cwes: list[str] | None = None,
    project_labels: list[str] | None = None,
    licenses: list[str] | None = None,
    severity: list[Severity] | None = None,
    severity_source: list[SeveritySource] | None = None,
    revision_ids: list[str] | None = None,
    found_after: datetime | None = None,
    notes: str | None = None,
    reason: IgnoreReason | None = None,
    package_scope: PackageScope | None = None,
    ignore_scope: IgnoreScope | None = None,
    expires_after: date | None = None,
    license_id: str | None = None,
) -> dict[str, Any]:
    """
    Ignore, unignore, unlink, or create a reusable exception for a set of
    issues.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true, and additionally
    FOSSA_ALLOW_DESTRUCTIVE=true when issue_ids is omitted.

    Passing issue_ids acts on exactly those issues. Omitting it acts on every
    issue matching the filters, a set the caller cannot see in advance, so that
    form is gated at the destructive tier and requires a project scope or at
    least one filter. Run fossa_list_issues with the same arguments first to see
    what will be affected.

    The issueException action creates a durable ignore rule rather than a
    one-off ignore; package_scope, ignore_scope, expires_after, and license_id
    only apply to it. Ticket export is not offered by this tool.
    """
    validated = IssueUpdateInput(
        action=action,
        category=category,
        issue_ids=issue_ids,
        status=status,
        scope_type=scope_type,
        project_locator=project_locator,
        revision_locator=revision_locator,
        search=search,
        depths=depths,
        issue_types=issue_types,
        package_managers=package_managers,
        cwes=cwes,
        project_labels=project_labels,
        licenses=licenses,
        severity=severity,
        severity_source=severity_source,
        revision_ids=revision_ids,
        found_after=found_after,
        notes=notes,
        reason=reason,
        package_scope=package_scope,
        ignore_scope=ignore_scope,
        expires_after=expires_after,
        license_id=license_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    # Tier follows blast radius: naming the issues is a write, sweeping a
    # filter is destructive.
    tier = WriteTier.DESTRUCTIVE if validated.targets_a_filter else WriteTier.WRITE
    require_tier(settings, tier, "fossa_update_issues")

    params: list[tuple[str, str]] = [
        ("category", validated.category),
        ("status", validated.status),
    ]
    params.extend(
        _scope_params(validated.scope_type, validated.project_locator, validated.revision_locator)
    )

    issue_id_strs = [str(i) for i in validated.issue_ids] if validated.issue_ids else None
    add_repeated(params, "ids", issue_id_strs)
    add_repeated(params, "filter[revisionIds]", validated.revision_ids)
    add_repeated(params, "filter[depths]", validated.depths)
    add_repeated(params, "filter[type]", validated.issue_types)
    add_repeated(params, "filter[packageManagers]", validated.package_managers)
    add_repeated(params, "filter[cwes]", validated.cwes)
    add_repeated(params, "filter[projectLabels]", validated.project_labels)
    add_repeated(params, "filter[licenses]", validated.licenses)
    add_repeated(params, "filter[severity]", validated.severity)
    add_repeated(params, "filter[severitySource]", validated.severity_source)

    if validated.search is not None:
        params.append(("filter[search]", validated.search))
    if validated.found_after is not None:
        params.append(("filter[foundAfter]", validated.found_after.isoformat()))

    body: dict[str, Any] = {"type": validated.action}
    if validated.notes is not None:
        body["notes"] = validated.notes
    if validated.reason is not None:
        body["reason"] = validated.reason
    if validated.action == "issueException":
        if validated.package_scope is not None:
            body["packageScope"] = validated.package_scope
        if validated.ignore_scope is not None:
            body["ignoreScope"] = validated.ignore_scope
        if validated.expires_after is not None:
            body["expiresAfter"] = validated.expires_after.isoformat()
        if validated.license_id is not None:
            body["licenseId"] = validated.license_id

    result = await client.request_json("PUT", "/v2/issues", params=params, json_body=body)

    return {
        "ok": True,
        "endpoint": "PUT /v2/issues",
        "data": {
            "applied": body,
            "targeted_issue_ids": validated.issue_ids,
            "targeted_by_filter": validated.targets_a_filter,
            "tier": tier.value,
            "result": result,
        },
    }


async def extend_issue_exception(
    ctx: Context,
    exception_id: int,
    expires_after: date | None,
) -> dict[str, Any]:
    """
    Change when an issue exception expires, or clear the expiry so it never
    does.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    expires_after has no default because null is meaningful here: it removes
    the expiry, leaving the issue ignored indefinitely. Pass a YYYY-MM-DD date
    to set one. Requires a premium FOSSA subscription.
    """
    validated = IssueExceptionExtendInput(exception_id=exception_id, expires_after=expires_after)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_extend_issue_exception")

    body: dict[str, Any] = {
        "expiresAfter": (
            validated.expires_after.isoformat() if validated.expires_after is not None else None
        )
    }

    # A successful update answers 204 with no body.
    result = await _request_tolerating_empty_body(
        client, "PUT", f"/v2/issues/exceptions/{validated.exception_id}", json_body=body
    )

    return {
        "ok": True,
        "endpoint": "PUT /v2/issues/exceptions/{id}",
        "data": {
            "exception_id": validated.exception_id,
            "applied": body,
            "result": result,
        },
    }


async def delete_issue_exceptions(
    ctx: Context,
    exception_id: int | None = None,
    exception_ids: list[int] | None = None,
    category: ExceptionDeleteCategory | None = None,
    project_id: str | None = None,
    release_group_id: int | None = None,
    policy_id: int | None = None,
) -> dict[str, Any]:
    """
    Delete issue ignore rules, which makes the issues they were suppressing
    active again.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    Pass exactly one target: exception_id for a single rule, exception_ids for
    a named list, or a filter (category, project_id, release_group_id,
    policy_id) to delete every rule matching it. The filter form must name at
    least one filter, so there is no way to clear an organization's exceptions
    in one call. Run fossa_get_issue_exceptions first to see what a filter
    covers.
    """
    validated = IssueExceptionDeleteInput(
        exception_id=exception_id,
        exception_ids=exception_ids,
        category=category,
        project_id=project_id,
        release_group_id=release_group_id,
        policy_id=policy_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_issue_exceptions")

    if validated.exception_id is not None:
        result = await client.request_json(
            "DELETE", f"/v2/issues/exceptions/{validated.exception_id}"
        )
        return {
            "ok": True,
            "endpoint": "DELETE /v2/issues/exceptions/{id}",
            "data": {"exception_id": validated.exception_id, "issues_unignored": result},
        }

    if validated.exception_ids is not None:
        body: dict[str, Any] = {"kind": "idList", "value": validated.exception_ids}
    else:
        filters: dict[str, Any] = {}
        if validated.category is not None:
            filters["category"] = validated.category
        if validated.project_id is not None:
            filters["projectId"] = validated.project_id
        if validated.release_group_id is not None:
            filters["releaseGroupId"] = validated.release_group_id
        if validated.policy_id is not None:
            filters["policyId"] = validated.policy_id
        body = {"kind": "all", "filters": filters}

    result = await client.request_json("DELETE", "/v2/issues/exceptions", json_body=body)

    return {
        "ok": True,
        "endpoint": "DELETE /v2/issues/exceptions",
        "data": {"applied": body, "result": result},
    }


async def create_issue_dispute(
    ctx: Context,
    issue_id: int,
    reason: DisputeReason,
    comment: str | None = None,
) -> dict[str, Any]:
    """
    Dispute a licensing or quality issue, telling FOSSA the finding is wrong.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    The dispute type follows the issue's own category, so the reason must match
    it: the INCORRECT_DEPENDENCY_VERSION_REPORTED, LICENSE_DETECTION_FALSE_
    POSITIVE, MULTI_OR_DUAL_LICENSED, and INCORRECT_LICENSE_CONCLUSION reasons
    are for licensing issues; INCORRECT_STALENESS_REPORTED, INCORRECTLY_FLAGGED_
    ABANDONWARE, and INCORRECTLY_FLAGGED_EMPTY are for quality issues.
    Vulnerability issues cannot be disputed.
    """
    validated = IssueDisputeInput(issue_id=issue_id, reason=reason, comment=comment)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_issue_dispute")

    body: dict[str, Any] = {"reason": validated.reason}
    if validated.comment is not None:
        body["comment"] = validated.comment

    result = await client.request_json(
        "POST", f"/v2/issues/{validated.issue_id}/disputes", json_body=body
    )

    return {
        "ok": True,
        "endpoint": "POST /v2/issues/{issueId}/disputes",
        "data": {"issue_id": validated.issue_id, "applied": body, "dispute": result},
    }


# --- issue overview ----------------------------------------------------------


def _overview_params(validated: IssueOverviewInput) -> list[tuple[str, str]]:
    """Build the query shared by the two /issue_counts endpoints."""
    params: list[tuple[str, str]] = []
    if validated.start is not None:
        params.append(("start", validated.start.isoformat()))
    if validated.end is not None:
        params.append(("end", validated.end.isoformat()))
    add_repeated(params, "labels", [str(i) for i in validated.label_ids or []] or None)
    if validated.category is not None:
        params.append(("category", validated.category))
    if validated.project_id is not None:
        params.append(("projectId", validated.project_id))
    _add_plain_repeated(params, "teamId", validated.team_ids)
    return params


async def get_issue_overview(
    ctx: Context,
    start: datetime | None = None,
    end: datetime | None = None,
    category: IssueCategory | None = None,
    project_id: str | None = None,
    label_ids: list[int] | None = None,
    team_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Retrieve daily active, ignored, and remediated issue counts over a date
    range.

    Read-only. This is the trend view behind FOSSA's Issue Overview: how the
    backlog moved, not what is in it.
    """
    validated = IssueOverviewInput(
        start=start,
        end=end,
        category=category,
        project_id=project_id,
        label_ids=label_ids,
        team_ids=team_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    result = await client.request_json("GET", "/issue_counts", params=_overview_params(validated))

    return {"ok": True, "endpoint": "GET /issue_counts", "data": result}


async def export_issue_overview(
    ctx: Context,
    start: datetime | None = None,
    end: datetime | None = None,
    category: IssueCategory | None = None,
    project_id: str | None = None,
    label_ids: list[int] | None = None,
    team_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Queue an export of the issues behind the Issue Overview counts.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This does not change any issue, but it does create a background job in the
    organization and deliver a report, so it is gated like any other POST.
    Returns the job token FOSSA uses to track the export; this server has no
    endpoint to poll it.
    """
    validated = IssueOverviewInput(
        start=start,
        end=end,
        category=category,
        project_id=project_id,
        label_ids=label_ids,
        team_ids=team_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_export_issue_overview")

    result = await client.request_json(
        "POST", "/issue_counts/export", params=_overview_params(validated)
    )

    return {"ok": True, "endpoint": "POST /issue_counts/export", "data": result}


# --- saved issue filters -----------------------------------------------------


async def get_issue_filters(
    ctx: Context,
    category: IssueCategory | None = None,
    filter_id: int | None = None,
) -> dict[str, Any]:
    """
    List the organization's saved issue filters for one category, or fetch one
    by id.

    Read-only. A saved filter records the criteria, sort, and grouping the
    FOSSA issue views use; reading one tells you what a team considers its
    working set.
    """
    validated = IssueFilterReadInput(category=category, filter_id=filter_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    if validated.filter_id is not None:
        result = await client.request_json("GET", f"/issue-filters/{validated.filter_id}")
        return {"ok": True, "endpoint": "GET /issue-filters/{filterId}", "data": result}

    assert validated.category is not None
    result = await client.request_json(
        "GET", "/issue-filters", params=[("category", validated.category)]
    )

    return {"ok": True, "endpoint": "GET /issue-filters", "data": result}


async def save_issue_filter(
    ctx: Context,
    name: str,
    criteria: dict[str, Any],
    filter_id: int | None = None,
    category: IssueCategory | None = None,
    sort: IssueFilterSort | None = None,
    group: IssueFilterGroup | None = None,
) -> dict[str, Any]:
    """
    Create a saved issue filter for the organization, or update an existing one.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Omit filter_id and pass category to create; pass filter_id to update. A
    filter's category is fixed at creation. `criteria` is the filter body FOSSA
    stores as-is, keyed by the same names the issue views use (severity,
    packageManagers, projectLabels, search, ticketed, cwes, and so on).
    Requires a premium FOSSA subscription.
    """
    validated = IssueFilterSaveInput(
        name=name,
        criteria=criteria,
        filter_id=filter_id,
        category=category,
        sort=sort,
        group=group,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_save_issue_filter")

    body: dict[str, Any] = {"name": validated.name, "filter": validated.criteria}
    if validated.category is not None:
        body["category"] = validated.category
    if validated.sort is not None:
        body["sort"] = validated.sort
    if validated.group is not None:
        body["group"] = validated.group

    if validated.filter_id is None:
        result = await client.request_json("POST", "/issue-filters", json_body=body)
        endpoint = "POST /issue-filters"
    else:
        result = await client.request_json(
            "PUT", f"/issue-filters/{validated.filter_id}", json_body=body
        )
        endpoint = "PUT /issue-filters/{filterId}"

    return {"ok": True, "endpoint": endpoint, "data": {"applied": body, "filter": result}}


async def delete_issue_filter(
    ctx: Context,
    filter_id: int,
) -> dict[str, Any]:
    """
    Delete a saved issue filter.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The filter must belong to the calling token's organization. Deleting it
    removes it for everyone who uses it.
    """
    validated = IssueFilterDeleteInput(filter_id=filter_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_issue_filter")

    # The 200 here is documented without a response body.
    result = await _request_tolerating_empty_body(
        client, "DELETE", f"/issue-filters/{validated.filter_id}"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /issue-filters/{filterId}",
        "data": {"filter_id": validated.filter_id, "result": result},
    }
