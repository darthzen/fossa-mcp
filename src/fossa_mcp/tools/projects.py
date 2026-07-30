"""Project-related tools for FOSSA MCP server."""

import asyncio
from typing import List, Optional, Any, Dict
from mcp.server import ToolContext
from pydantic import BaseModel

from ..client import FossaClient
from ..models import ProjectListInput, ToolResponse
from ..query import add_repeated, bool_to_str


async def list_projects(
    context: ToolContext,
    input: ProjectListInput,
) -> ToolResponse:
    """
    List FOSSA projects visible to the current account.

    Use this first when the user names a project informally or asks for an
    organization-wide project inventory. Supports sorting by licensing, security,
    quality, scan time, and title.

    Args:
        context: MCP tool context
        input: Input parameters

    Returns:
        Tool response with project list
    """
    # Validate inputs
    if input.page < 1:
        raise ValueError("Page must be >= 1")
    if not (1 <= input.count <= context.settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {context.settings.fossa_max_page_size}")
    if input.latest_scan_days is not None and input.latest_scan_days < 0:
        raise ValueError("latest_scan_days must be >= 0")
    if input.last_revision_within_days is not None and input.last_revision_within_days < 0:
        raise ValueError("last_revision_within_days must be >= 0")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add simple parameters
    if input.title is not None:
        params.append(("title", input.title))

    # Add repeated parameters
    add_repeated(params, "type", input.types)
    add_repeated(params, "labels", input.labels)
    add_repeated(params, "teamId", input.team_ids)
    add_repeated(params, "locators", input.locators)
    add_repeated(params, "inventory", input.inventory)

    # Add boolean parameters
    if input.is_public is not None:
        params.append(("isPublic", bool_to_str(input.is_public)))

    if input.latest_scan_days is not None:
        params.append(("latestScan", str(input.latest_scan_days)))

    if input.last_revision_within_days is not None:
        params.append(("lastRevisionWithin", str(input.last_revision_within_days)))

    if input.include_shared_projects is not None:
        params.append(("includeSharedProjects", bool_to_str(input.include_shared_projects)))

    if input.only_include_shared_projects is not None:
        params.append(("onlyIncludeSharedProjects", bool_to_str(input.only_include_shared_projects)))

    # Add sort parameter
    if input.sort is not None:
        params.append(("sort", input.sort))

    # Add pagination
    params.append(("page", str(input.page)))
    params.append(("count", str(input.count)))

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", "/v2/projects", params=params)

    return ToolResponse(
        endpoint="GET /v2/projects",
        data=result
    )


async def get_project(
    context: ToolContext,
    project_locator: str,
    ref: Optional[str] = None,
    ref_type: str = "branch",
) -> ToolResponse:
    """
    Get detailed metadata about exactly one FOSSA project.

    Use the exact FOSSA locator returned by another FOSSA MCP tool. Do not guess it from a repository name.

    Args:
        context: MCP tool context
        project_locator: The project locator to get details for
        ref: Optional reference (branch or tag)
        ref_type: Type of reference ("branch" or "tag")

    Returns:
        Tool response with project details
    """
    # Validate inputs
    if not project_locator:
        raise ValueError("Project locator must not be blank")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add reference parameters if provided
    if ref is not None:
        params.append(("ref", ref))
        params.append(("refType", ref_type))

    # Encode the locator in the path (exactly once)
    encoded_locator = project_locator  # This will be URL-encoded by the client

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", f"/projects/{encoded_locator}", params=params)

    return ToolResponse(
        endpoint="GET /projects/{locator}",
        data=result
    )