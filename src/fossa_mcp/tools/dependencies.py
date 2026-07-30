"""Dependency-related tools for the FOSSA MCP server."""

from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import (
    Confidence,
    DependencyDepth,
    DependencyListInput,
    DependencySource,
    DependencyStatus,
    HasIssues,
    LayerDepth,
)
from ..query import add_repeated, bool_to_str


async def list_dependencies(
    ctx: Context,
    revision_locator: str,
    dependency_locators: list[str] | None = None,
    title: str | None = None,
    statuses: list[DependencyStatus] | None = None,
    depths: list[DependencyDepth] | None = None,
    layer_depths: list[LayerDepth] | None = None,
    has_issues: list[HasIssues] | None = None,
    licenses: list[str] | None = None,
    fetchers: list[str] | None = None,
    show_ignored: bool = False,
    confidence: list[Confidence] | None = None,
    sources: list[DependencySource] | None = None,
    package_labels: list[str] | None = None,
    vendored_path: str | None = None,
    include_resolution_notes: bool = False,
    include_license_text: bool = False,
    include_copyright: bool = False,
    include_matches: bool = False,
    include_download_url: bool = False,
    page: int = 1,
    count: int = 20,
) -> dict[str, Any]:
    """
    List dependencies detected in a specific project revision, with filters
    useful for licensing/security investigation.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = DependencyListInput(
        revision_locator=revision_locator,
        dependency_locators=dependency_locators,
        title=title,
        statuses=statuses,
        depths=depths,
        layer_depths=layer_depths,
        has_issues=has_issues,
        licenses=licenses,
        fetchers=fetchers,
        show_ignored=show_ignored,
        confidence=confidence,
        sources=sources,
        package_labels=package_labels,
        vendored_path=vendored_path,
        include_resolution_notes=include_resolution_notes,
        include_license_text=include_license_text,
        include_copyright=include_copyright,
        include_matches=include_matches,
        include_download_url=include_download_url,
        page=page,
        count=count,
    )
    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    params: list[tuple[str, str]] = []

    add_repeated(params, "locators", validated.dependency_locators)
    add_repeated(params, "status", validated.statuses)
    add_repeated(params, "depth", validated.depths)
    add_repeated(params, "layerDepth", validated.layer_depths)
    add_repeated(params, "hasIssues", validated.has_issues)
    add_repeated(params, "licenses", validated.licenses)
    add_repeated(params, "fetchers", validated.fetchers)
    add_repeated(params, "confidence", validated.confidence)
    add_repeated(params, "sources", validated.sources)
    add_repeated(params, "packageLabels", validated.package_labels)

    if validated.title is not None:
        params.append(("title", validated.title))

    if validated.show_ignored:
        params.append(("showIgnored", bool_to_str(validated.show_ignored)))

    if validated.vendored_path is not None:
        params.append(("vendoredPath", validated.vendored_path))

    params.append(("includeResolutionNotes", bool_to_str(validated.include_resolution_notes)))
    params.append(("includeLicenseText", bool_to_str(validated.include_license_text)))
    params.append(("includeCopyright", bool_to_str(validated.include_copyright)))
    params.append(("includeMatches", bool_to_str(validated.include_matches)))
    params.append(("includeDownloadUrl", bool_to_str(validated.include_download_url)))

    params.append(("page", str(validated.page)))
    params.append(("count", str(validated.count)))

    encoded_locator = quote(validated.revision_locator, safe="")

    result = await client.request_json(
        "GET", f"/v2/revisions/{encoded_locator}/dependencies", params=params
    )

    return {
        "ok": True,
        "endpoint": "GET /v2/revisions/{locator}/dependencies",
        "data": result,
    }


async def get_dependency(
    ctx: Context,
    revision_locator: str,
    dependency_revision_locator: str,
    include_resolution_notes: bool = True,
    include_license_text: bool = False,
    include_copyright: bool = False,
    include_matches: bool = False,
    include_download_url: bool = False,
) -> dict[str, Any]:
    """
    Get the richer detail record for one dependency in one revision.

    Use the exact dependency revision locator returned by
    `fossa_list_dependencies`.
    """
    if not revision_locator:
        raise ValueError("Revision locator must not be blank")
    if not dependency_revision_locator:
        raise ValueError("Dependency revision locator must not be blank")

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [
        ("includeResolutionNotes", bool_to_str(include_resolution_notes)),
        ("includeLicenseText", bool_to_str(include_license_text)),
        ("includeCopyright", bool_to_str(include_copyright)),
        ("includeMatches", bool_to_str(include_matches)),
        ("includeDownloadUrl", bool_to_str(include_download_url)),
    ]

    encoded_revision_locator = quote(revision_locator, safe="")
    encoded_dependency_locator = quote(dependency_revision_locator, safe="")

    result = await client.request_json(
        "GET",
        f"/v2/revisions/{encoded_revision_locator}/dependencies/{encoded_dependency_locator}",
        params=params,
    )

    return {
        "ok": True,
        "endpoint": "GET /v2/revisions/{locator}/dependencies/{dependencyRevisionLocator}",
        "data": result,
    }
