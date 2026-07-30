"""Issue-related tools for FOSSA MCP server."""

import asyncio
from typing import List, Optional, Any, Dict
from datetime import datetime
from mcp.server import ToolContext

from ..client import FossaClient
from ..models import IssueListInput, ToolResponse
from ..query import add_repeated, bool_to_str


async def list_issues(
    context: ToolContext,
    category: str,
    status: str = "active",
    scope_type: str = "global",
    project_locator: Optional[str] = None,
    revision_locator: Optional[str] = None,
    compare_to_revision: Optional[str] = None,
    change_status: Optional[str] = None,
    issue_ids: Optional[List[int]] = None,
    search: Optional[str] = None,
    depths: Optional[List[str]] = None,
    issue_types: Optional[List[str]] = None,
    package_managers: Optional[List[str]] = None,
    cwes: Optional[List[str]] = None,
    project_labels: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    severity_source: Optional[List[str]] = None,
    found_before: Optional[datetime] = None,
    found_after: Optional[datetime] = None,
    issue_source: Optional[List[str]] = None,
    sort: Optional[str] = None,
    include_direct_dependency_origin_paths: bool = False,
    page: int = 1,
    count: int = 20,
) -> ToolResponse:
    """
    Query licensing, vulnerability, or quality issues globally or for one project revision.

    Supports comparing issues between revisions.

    Args:
        context: MCP tool context
        category: Issue category ("licensing", "vulnerability", or "quality")
        status: Issue status ("active" or "ignored")
        scope_type: Scope type ("global" or "project")
        project_locator: Project locator (required for project scope)
        revision_locator: Revision locator (required for project scope)
        compare_to_revision: Revision to compare against
        change_status: Change status for comparison
        issue_ids: Filter by specific issue IDs
        search: Search term
        depths: Filter by depth
        issue_types: Filter by issue type
        package_managers: Filter by package manager
        cwes: Filter by CWE IDs
        project_labels: Filter by project labels
        severity: Filter by severity (vulnerability category only)
        severity_source: Filter by severity source (vulnerability category only)
        found_before: Filter issues found before date
        found_after: Filter issues found after date
        issue_source: Filter by issue source
        sort: Sort order
        include_direct_dependency_origin_paths: Include direct dependency origin paths
        page: Page number for pagination
        count: Number of results per page

    Returns:
        Tool response with issues
    """
    # Validate inputs
    if page < 1:
        raise ValueError("Page must be >= 1")
    if not (1 <= count <= context.settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {context.settings.fossa_max_page_size}")

    # Validation for scope_type combinations
    if scope_type == "global":
        if project_locator is not None:
            raise ValueError("project_locator must be None for global scope")
        if revision_locator is not None:
            raise ValueError("revision_locator must be None for global scope")
        if compare_to_revision is not None:
            raise ValueError("compare_to_revision must be None for global scope")
        if change_status is not None:
            raise ValueError("change_status must be None for global scope")
    elif scope_type == "project":
        if project_locator is None:
            raise ValueError("project_locator is required for project scope")
        if revision_locator is None:
            raise ValueError("revision_locator is required for project scope")

        # Validate that comparison parameters are used together
        if (compare_to_revision is not None) != (change_status is not None):
            raise ValueError("compare_to_revision and change_status must be set together or both unset")

    # Validate category-specific parameters
    if category == "vulnerability":
        # Vulnerability category can have severity and severity_source filters
        pass
    else:
        # Other categories should not have these filters
        if severity is not None:
            raise ValueError("severity filter is only allowed for vulnerability category")
        if severity_source is not None:
            raise ValueError("severity_source filter is only allowed for vulnerability category")
        if cwes is not None:
            raise ValueError("cwes filter is only allowed for vulnerability category")

    # For vulnerability category, issue_types should be rejected to keep contract deterministic
    if category == "vulnerability" and issue_types is not None:
        raise ValueError("issue_types is not allowed for vulnerability category")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add required base parameters
    params.append(("category", category))
    params.append(("status", status))
    params.append(("scope[type]", scope_type))
    params.append(("page", str(page)))
    params.append(("count", str(count)))

    # Add scope-specific parameters
    if scope_type == "project":
        params.append(("scope[id]", project_locator))
        params.append(("scope[revision]", revision_locator))

        # Add comparison parameters if provided
        if compare_to_revision is not None:
            params.append(("scope[compareTo][revision]", compare_to_revision))
            params.append(("scope[compareTo][changeStatus]", change_status))

    # Add repeated parameters
    add_repeated(params, "ids", issue_ids)
    add_repeated(params, "filter[depths]", depths)
    add_repeated(params, "filter[type]", issue_types)
    add_repeated(params, "filter[packageManagers]", package_managers)
    add_repeated(params, "filter[cwes]", cwes)
    add_repeated(params, "filter[projectLabels]", project_labels)
    add_repeated(params, "filter[severity]", severity)
    add_repeated(params, "filter[severitySource]", severity_source)
    add_repeated(params, "filter[issueSource]", issue_source)

    # Add simple parameters
    if search is not None:
        params.append(("filter[search]", search))

    # Add date filters (if provided)
    if found_before is not None:
        params.append(("filter[foundBefore]", found_before.isoformat()))

    if found_after is not None:
        params.append(("filter[foundAfter]", found_after.isoformat()))

    # Add sort parameter
    if sort is not None:
        params.append(("sort", sort))

    # Add boolean parameters
    params.append(("includeDirectDependencyOriginPaths", bool_to_str(include_direct_dependency_origin_paths)))

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", "/v2/issues", params=params)

    # Check if we got a 202 (analysis in progress) response
    # We need to check this after making the request but before returning
    return ToolResponse(
        endpoint="GET /v2/issues",
        data=result
    )


async def get_issue(
    context: ToolContext,
    issue_id: int,
    category: str,
    scope_type: str = "global",
    project_locator: Optional[str] = None,
    revision_locator: Optional[str] = None,
) -> ToolResponse:
    """
    Retrieve complete detail for one issue.

    Args:
        context: MCP tool context
        issue_id: The ID of the issue to retrieve
        category: Issue category ("licensing", "vulnerability", or "quality")
        scope_type: Scope type ("global" or "project")
        project_locator: Project locator (required for project scope)
        revision_locator: Revision locator (required for project scope)

    Returns:
        Tool response with issue details
    """
    # Validate inputs
    if issue_id < 1:
        raise ValueError("Issue ID must be >= 1")

    if scope_type == "global":
        if project_locator is not None:
            raise ValueError("project_locator must be None for global scope")
        if revision_locator is not None:
            raise ValueError("revision_locator must be None for global scope")
    elif scope_type == "project":
        if project_locator is None:
            raise ValueError("project_locator is required for project scope")
        if revision_locator is None:
            raise ValueError("revision_locator is required for project scope")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add base parameters
    params.append(("category", category))
    params.append(("scope[type]", scope_type))

    # Add scope-specific parameters
    if scope_type == "project":
        params.append(("scope[id]", project_locator))
        params.append(("scope[revision]", revision_locator))

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", f"/v2/issues/{issue_id}", params=params)

    return ToolResponse(
        endpoint="GET /v2/issues/{issueId}",
        data=result
    )