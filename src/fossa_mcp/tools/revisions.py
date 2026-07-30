"""Revision-related tools for the FOSSA MCP server."""

from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import RefType, RevisionListInput, RevisionSource
from ..query import add_repeated, bool_to_str


async def list_project_revisions(
    ctx: Context,
    project_locator: str,
    offset: int = 0,
    count: int = 20,
    resolved_only: bool = True,
    refs: list[str] | None = None,
    refs_type: RefType | None = None,
    source: RevisionSource | None = None,
    minimal: bool = True,
    locator_contains: str | None = None,
) -> dict[str, Any]:
    """
    List analyzed revisions, branches, or tags for a project.

    Use the full revision locator returned by FOSSA, including any `$revision`
    suffix.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = RevisionListInput(
        project_locator=project_locator,
        offset=offset,
        count=count,
        resolved_only=resolved_only,
        refs=refs,
        refs_type=refs_type,
        source=source,
        minimal=minimal,
        locator_contains=locator_contains,
    )
    max_count = min(settings.fossa_max_page_size, 1000)
    if not (1 <= validated.count <= max_count):
        raise ValueError(f"Count must be between 1 and {max_count}")

    params: list[tuple[str, str]] = []

    if validated.offset != 0:
        params.append(("offset", str(validated.offset)))

    params.append(("count", str(validated.count)))
    params.append(("resolved", bool_to_str(validated.resolved_only)))

    add_repeated(params, "refs", validated.refs)

    if validated.refs_type is not None:
        params.append(("refs_type", validated.refs_type))

    if validated.source is not None:
        params.append(("source", validated.source))

    params.append(("isMinimal", bool_to_str(validated.minimal)))

    if validated.locator_contains is not None:
        params.append(("locator", validated.locator_contains))

    encoded_locator = quote(validated.project_locator, safe="")

    result = await client.request_json(
        "GET", f"/projects/{encoded_locator}/revisions", params=params
    )

    return {"ok": True, "endpoint": "GET /projects/{locator}/revisions", "data": result}
