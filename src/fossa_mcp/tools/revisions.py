"""Revision-related tools for FOSSA MCP server."""

import asyncio
from typing import List, Optional, Any
from mcp.server import ToolContext

from ..client import FossaClient
from ..models import RevisionListInput, ToolResponse
from ..query import add_repeated, bool_to_str


async def list_project_revisions(
    context: ToolContext,
    project_locator: str,
    offset: int = 0,
    count: int = 20,
    resolved_only: bool = True,
    refs: Optional[List[str]] = None,
    refs_type: Optional[str] = None,
    source: Optional[str] = None,
    minimal: bool = True,
    locator_contains: Optional[str] = None,
) -> ToolResponse:
    """
    List analyzed revisions, branches, or tags for a project.

    Use the full revision locator returned by FOSSA, including any `$revision` suffix.

    Args:
        context: MCP tool context
        project_locator: The project locator to get revisions for
        offset: Offset for pagination
        count: Number of results to return
        resolved_only: Only return resolved revisions
        refs: List of reference names to filter by
        refs_type: Type of references ("branch" or "tag")
        source: Source type to filter by
        minimal: Return minimal revision data
        locator_contains: Filter by locator containing this string

    Returns:
        Tool response with project revisions
    """
    # Validate inputs
    if offset < 0:
        raise ValueError("Offset must be >= 0")
    if not (1 <= count <= min(context.settings.fossa_max_page_size, 1000)):
        raise ValueError(f"Count must be between 1 and {min(context.settings.fossa_max_page_size, 1000)}")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add simple parameters
    if offset != 0:
        params.append(("offset", str(offset)))

    params.append(("count", str(count)))
    params.append(("resolved", bool_to_str(resolved_only)))

    # Add repeated parameters
    add_repeated(params, "refs", refs)

    # Add other parameters
    if refs_type is not None:
        params.append(("refs_type", refs_type))

    if source is not None:
        params.append(("source", source))

    params.append(("isMinimal", bool_to_str(minimal)))

    if locator_contains is not None:
        params.append(("locator", locator_contains))

    # Encode the locator in the path (exactly once)
    encoded_locator = project_locator  # This will be URL-encoded by the client

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", f"/projects/{encoded_locator}/revisions", params=params)

    return ToolResponse(
        endpoint="GET /projects/{locator}/revisions",
        data=result
    )