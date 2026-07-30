"""Dependency-related tools for FOSSA MCP server."""

import asyncio
from typing import List, Optional, Any
from mcp.server import ToolContext

from ..client import FossaClient
from ..models import DependencyListInput, ToolResponse
from ..query import add_repeated, bool_to_str


async def list_dependencies(
    context: ToolContext,
    revision_locator: str,
    dependency_locators: Optional[List[str]] = None,
    title: Optional[str] = None,
    statuses: Optional[List[str]] = None,
    depths: Optional[List[str]] = None,
    layer_depths: Optional[List[str]] = None,
    has_issues: Optional[List[str]] = None,
    licenses: Optional[List[str]] = None,
    fetchers: Optional[List[str]] = None,
    show_ignored: bool = False,
    confidence: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    package_labels: Optional[List[str]] = None,
    vendored_path: Optional[str] = None,
    include_resolution_notes: bool = False,
    include_license_text: bool = False,
    include_copyright: bool = False,
    include_matches: bool = False,
    include_download_url: bool = False,
    page: int = 1,
    count: int = 20,
) -> ToolResponse:
    """
    List dependencies detected in a specific project revision, with filters useful for licensing/security investigation.

    Args:
        context: MCP tool context
        revision_locator: The revision locator to get dependencies for
        dependency_locators: Filter by specific dependency locators
        title: Filter by dependency title
        statuses: Filter by dependency status
        depths: Filter by depth (direct, transitive)
        layer_depths: Filter by layer depth
        has_issues: Filter by issue presence
        licenses: Filter by license
        fetchers: Filter by fetcher
        show_ignored: Show ignored dependencies
        confidence: Filter by confidence level
        sources: Filter by source type
        package_labels: Filter by package labels
        vendored_path: Filter by vendored path
        include_resolution_notes: Include resolution notes
        include_license_text: Include license text
        include_copyright: Include copyright information
        include_matches: Include matches
        include_download_url: Include download URL
        page: Page number for pagination
        count: Number of results per page

    Returns:
        Tool response with dependencies
    """
    # Validate inputs
    if page < 1:
        raise ValueError("Page must be >= 1")
    if not (1 <= count <= context.settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {context.settings.fossa_max_page_size}")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add repeated parameters
    add_repeated(params, "locators", dependency_locators)
    add_repeated(params, "status", statuses)
    add_repeated(params, "depth", depths)
    add_repeated(params, "layerDepth", layer_depths)
    add_repeated(params, "hasIssues", has_issues)
    add_repeated(params, "licenses", licenses)
    add_repeated(params, "fetchers", fetchers)
    add_repeated(params, "confidence", confidence)
    add_repeated(params, "sources", sources)
    add_repeated(params, "packageLabels", package_labels)

    # Add simple parameters
    if title is not None:
        params.append(("title", title))

    if show_ignored:
        params.append(("showIgnored", bool_to_str(show_ignored)))

    if vendored_path is not None:
        params.append(("vendoredPath", vendored_path))

    # Add boolean parameters (default to false for expensive fields)
    params.append(("includeResolutionNotes", bool_to_str(include_resolution_notes)))
    params.append(("includeLicenseText", bool_to_str(include_license_text)))
    params.append(("includeCopyright", bool_to_str(include_copyright)))
    params.append(("includeMatches", bool_to_str(include_matches)))
    params.append(("includeDownloadUrl", bool_to_str(include_download_url)))

    # Add pagination
    params.append(("page", str(page)))
    params.append(("count", str(count)))

    # Encode the locator in the path (exactly once)
    encoded_locator = revision_locator  # This will be URL-encoded by the client

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json("GET", f"/v2/revisions/{encoded_locator}/dependencies", params=params)

    return ToolResponse(
        endpoint="GET /v2/revisions/{locator}/dependencies",
        data=result
    )


async def get_dependency(
    context: ToolContext,
    revision_locator: str,
    dependency_revision_locator: str,
    include_resolution_notes: bool = True,
    include_license_text: bool = False,
    include_copyright: bool = False,
    include_matches: bool = False,
    include_download_url: bool = False,
) -> ToolResponse:
    """
    Get the richer detail record for one dependency in one revision.

    Use the exact dependency revision locator returned by `fossa_list_dependencies`.

    Args:
        context: MCP tool context
        revision_locator: The revision locator containing the dependency
        dependency_revision_locator: The specific dependency locator
        include_resolution_notes: Include resolution notes
        include_license_text: Include license text
        include_copyright: Include copyright information
        include_matches: Include matches
        include_download_url: Include download URL

    Returns:
        Tool response with dependency details
    """
    # Validate inputs
    if not revision_locator:
        raise ValueError("Revision locator must not be blank")
    if not dependency_revision_locator:
        raise ValueError("Dependency revision locator must not be blank")

    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add boolean parameters (default to false for expensive fields)
    params.append(("includeResolutionNotes", bool_to_str(include_resolution_notes)))
    params.append(("includeLicenseText", bool_to_str(include_license_text)))
    params.append(("includeCopyright", bool_to_str(include_copyright)))
    params.append(("includeMatches", bool_to_str(include_matches)))
    params.append(("includeDownloadUrl", bool_to_str(include_download_url)))

    # Encode locators in the path (exactly once)
    encoded_revision_locator = revision_locator  # This will be URL-encoded by the client
    encoded_dependency_locator = dependency_revision_locator  # This will be URL-encoded by the client

    # Make the API call
    client: FossaClient = context.state["client"]
    result = await client.request_json(
        "GET",
        f"/v2/revisions/{encoded_revision_locator}/dependencies/{encoded_dependency_locator}",
        params=params
    )

    return ToolResponse(
        endpoint="GET /v2/revisions/{locator}/dependencies/{dependencyRevisionLocator}",
        data=result
    )