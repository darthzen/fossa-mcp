"""Project-related tools for the FOSSA MCP server."""

from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import InventoryType, ProjectListInput, ProjectSort, ProjectType, RefType
from ..query import add_repeated, bool_to_str


async def list_projects(
    ctx: Context,
    title: str | None = None,
    types: list[ProjectType] | None = None,
    is_public: bool | None = None,
    labels: list[str] | None = None,
    team_ids: list[str] | None = None,
    latest_scan_days: int | None = None,
    last_revision_within_days: int | None = None,
    locators: list[str] | None = None,
    include_shared_projects: bool | None = None,
    only_include_shared_projects: bool | None = None,
    inventory: list[InventoryType] | None = None,
    sort: ProjectSort | None = None,
    page: int = 1,
    count: int = 20,
) -> dict[str, Any]:
    """
    List FOSSA projects visible to the current account.

    Use this first when the user names a project informally or asks for an
    organization-wide project inventory. Supports sorting by licensing, security,
    quality, scan time, and title.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = ProjectListInput(
        title=title,
        types=types,
        is_public=is_public,
        labels=labels,
        team_ids=team_ids,
        latest_scan_days=latest_scan_days,
        last_revision_within_days=last_revision_within_days,
        locators=locators,
        include_shared_projects=include_shared_projects,
        only_include_shared_projects=only_include_shared_projects,
        inventory=inventory,
        sort=sort,
        page=page,
        count=count,
    )
    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    params: list[tuple[str, str]] = []

    if validated.title is not None:
        params.append(("title", validated.title))

    add_repeated(params, "type", validated.types)
    add_repeated(params, "labels", validated.labels)
    add_repeated(params, "teamId", validated.team_ids)
    add_repeated(params, "locators", validated.locators)
    add_repeated(params, "inventory", validated.inventory)

    if validated.is_public is not None:
        params.append(("isPublic", bool_to_str(validated.is_public)))

    if validated.latest_scan_days is not None:
        params.append(("latestScan", str(validated.latest_scan_days)))

    if validated.last_revision_within_days is not None:
        params.append(("lastRevisionWithin", str(validated.last_revision_within_days)))

    if validated.include_shared_projects is not None:
        params.append(("includeSharedProjects", bool_to_str(validated.include_shared_projects)))

    if validated.only_include_shared_projects is not None:
        params.append(
            ("onlyIncludeSharedProjects", bool_to_str(validated.only_include_shared_projects))
        )

    if validated.sort is not None:
        params.append(("sort", validated.sort))

    params.append(("page", str(validated.page)))
    params.append(("count", str(validated.count)))

    result = await client.request_json("GET", "/v2/projects", params=params)

    return {"ok": True, "endpoint": "GET /v2/projects", "data": result}


async def get_project(
    ctx: Context,
    project_locator: str,
    ref: str | None = None,
    ref_type: RefType = "branch",
) -> dict[str, Any]:
    """
    Get detailed metadata about exactly one FOSSA project.

    Use the exact FOSSA locator returned by another FOSSA MCP tool. Do not
    guess it from a repository name.
    """
    if not project_locator:
        raise ValueError("Project locator must not be blank")

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = []
    if ref is not None:
        params.append(("ref", ref))
        # `ref_type`, not `refType`: getProject uses the snake_case key, the
        # same as getProjectRevisions' `refs_type`.
        params.append(("ref_type", ref_type))

    encoded_locator = quote(project_locator, safe="")

    result = await client.request_json("GET", f"/projects/{encoded_locator}", params=params)

    return {"ok": True, "endpoint": "GET /projects/{locator}", "data": result}
