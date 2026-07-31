"""Release group tools for the FOSSA MCP server.

A release group in FOSSA is a named set of projects, each pinned to a branch and
a revision, grouped under one or more releases — "Platform 2026.1" holding the
eleven services that shipped together. Issues, licenses, and obligations are
then reported across the whole release rather than per project.

What FOSSA's API actually supports, which is what shapes these tools:

* The domain is addressed by numeric ids only. A release group has an integer
  id, and a release has its own integer id scoped to that group. Neither has a
  slug, and the paths still use FOSSA's older `/project_group` spelling even
  though the product calls them release groups.
* There is no list-release-groups endpoint under this tag. `GET /v2/release-groups`
  exists but belongs to the Projects tag, so a caller who does not already know
  the id finds it there or in the release group's FOSSA URL.
* A release group cannot be created empty. `POST /project_group` requires an
  initial release with its projects in the same body, so `create_release_group`
  requires them too.
* Six per-release reads (`release`, `summary`, `licenses`, `obligations`,
  `revisions`, `scans`) are separate endpoints that take no parameters and differ
  only in the trailing path segment. They are exposed as one tool with a
  validated `sections` list rather than six near-identical tools, so a caller can
  fetch what it needs in one call. The same applies to the three release group
  reads.
* Attribution reporting has two entry points with different semantics. The v2
  endpoint streams a report back synchronously and is a plain read; the v1
  endpoint queues a background job, can publish to the SBOM portal, and returns
  a task id to poll. They are separate tools at separate tiers for that reason.

Deletes here remove FOSSA state that nothing else recreates, so both are
`DESTRUCTIVE`.
"""

import json
from collections.abc import Sequence
from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models.release_groups import (
    AttributionDependencyInfoOption,
    AttributionDependencyInfoOptionV2,
    AttributionOptions,
    AttributionTaskStatusInput,
    ReleaseCreateInput,
    ReleaseDeleteInput,
    ReleaseGroupAttributionInput,
    ReleaseGroupAttributionQueueInput,
    ReleaseGroupClearableField,
    ReleaseGroupCreateInput,
    ReleaseGroupDeleteInput,
    ReleaseGroupReadInput,
    ReleaseGroupReleaseListInput,
    ReleaseGroupReportFormat,
    ReleaseGroupSection,
    ReleaseGroupTextReportFormat,
    ReleaseGroupUpdateInput,
    ReleaseProject,
    ReleaseReadInput,
    ReleaseSection,
    ReleaseUpdateInput,
)
from ..query import bool_to_str
from ..writes import WriteTier, require_tier

# Section name -> path suffix appended to the release group or release base path.
_RELEASE_GROUP_SECTION_SUFFIX: dict[str, str] = {
    "group": "",
    "teams": "/teams",
    "projects": "/all_projects",
}

_RELEASE_SECTION_SUFFIX: dict[str, str] = {
    "release": "",
    "summary": "/summary",
    "licenses": "/licenses",
    "obligations": "/obligations",
    "revisions": "/revisions",
    "scans": "/scans",
}

_TEXT_REPORT_FORMATS = ("MD", "TXT", "CSV", "HTML", "SPDX", "CYCLONEDX_XML")


# --- reads -------------------------------------------------------------------


async def get_release_group(
    ctx: Context,
    release_group_id: int,
    sections: list[ReleaseGroupSection] | None = None,
) -> dict[str, Any]:
    """
    Get a FOSSA release group by its numeric id, optionally with the teams
    assigned to it and the projects it contains.

    Read-only. `release_group_id` is the integer in the release group's FOSSA
    URL. Sections: "group" is the release group record and its releases, "teams"
    is the assigned teams, "projects" is every project locator in the group
    across all releases. Defaults to "group" alone.
    """
    validated = ReleaseGroupReadInput(
        release_group_id=release_group_id,
        sections=sections or ["group"],
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    base = f"/project_group/{validated.release_group_id}"
    data: dict[str, Any] = {}
    for section in validated.sections:
        data[section] = await client.request_json(
            "GET", f"{base}{_RELEASE_GROUP_SECTION_SUFFIX[section]}"
        )

    return {
        "ok": True,
        "endpoint": _endpoint_list(
            "/project_group/{groupId}", _RELEASE_GROUP_SECTION_SUFFIX, validated.sections
        ),
        "data": data,
    }


async def list_release_group_releases(
    ctx: Context,
    release_group_id: int,
    page: int = 1,
    count: int = 10,
    search: str | None = None,
) -> dict[str, Any]:
    """
    List the releases in a FOSSA release group, paginated.

    Read-only. FOSSA caps `count` at 50 on this endpoint. `search` filters by
    release title. The unpaginated `/project_group/{id}/release` endpoint is
    deprecated by FOSSA and is not exposed.
    """
    validated = ReleaseGroupReleaseListInput(
        release_group_id=release_group_id,
        page=page,
        count=count,
        search=search,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    if validated.count > settings.fossa_max_page_size:
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    params: list[tuple[str, str]] = [
        ("page", str(validated.page)),
        ("count", str(validated.count)),
    ]
    if validated.search is not None:
        params.append(("search", validated.search))

    result = await client.request_json(
        "GET", f"/project_group/{validated.release_group_id}/releases", params=params
    )

    return {"ok": True, "endpoint": "GET /project_group/{groupId}/releases", "data": result}


async def get_release_group_release(
    ctx: Context,
    release_group_id: int,
    release_id: int,
    sections: list[ReleaseSection] | None = None,
) -> dict[str, Any]:
    """
    Get one release inside a FOSSA release group, and any of its rolled-up
    license, obligation, revision, scan, and issue-count views.

    Read-only. Sections: "release" is the release and its pinned projects,
    "summary" is the issue, project, and dependency counts, "licenses" and
    "obligations" are the license rollups keyed by license id, "revisions" is the
    revisions in the release, "scans" is the release scan history. Defaults to
    "release" and "summary". Each section costs one FOSSA request, so ask only
    for what is needed.
    """
    validated = ReleaseReadInput(
        release_group_id=release_group_id,
        release_id=release_id,
        sections=sections or ["release", "summary"],
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    base = f"/project_group/{validated.release_group_id}/release/{validated.release_id}"
    data: dict[str, Any] = {}
    for section in validated.sections:
        data[section] = await client.request_json(
            "GET", f"{base}{_RELEASE_SECTION_SUFFIX[section]}"
        )

    return {
        "ok": True,
        "endpoint": _endpoint_list(
            "/project_group/{groupId}/release/{releaseId}",
            _RELEASE_SECTION_SUFFIX,
            validated.sections,
        ),
        "data": data,
    }


async def get_release_group_attribution_report(
    ctx: Context,
    release_group_id: int,
    release_id: int,
    format: ReleaseGroupTextReportFormat = "MD",
    preview: bool = False,
    include_deep_dependencies: bool = True,
    include_direct_dependencies: bool = True,
    include_fossa_dependencies: bool = False,
    include_license_list: bool = True,
    include_license_scan: bool = False,
    include_project_license: bool = True,
    include_copyright_list: bool = False,
    include_file_matches: bool = False,
    include_open_vulnerabilities: bool = False,
    include_closed_vulnerabilities: bool = False,
    include_dependency_summary: bool = True,
    include_license_headers: bool = False,
    include_package_labels: bool = False,
    dependency_info_options: list[AttributionDependencyInfoOptionV2] | None = None,
    exclude_package_labels: list[str] | None = None,
    release_group_title: str | None = None,
    release_title: str | None = None,
    release_group_url: str | None = None,
) -> dict[str, Any]:
    """
    Generate and return an attribution or SBOM report for one release in a FOSSA
    release group, synchronously.

    Read-only. The report is streamed back rather than queued, and the portal
    publishing switch this endpoint also offers is deliberately not exposed here
    because publishing is a write; use fossa_queue_release_group_attribution_report
    for that. PDF is not offered because the response is decoded as text.
    `exclude_package_labels` drops every dependency carrying any of the named
    package labels.
    """
    validated = ReleaseGroupAttributionInput(
        release_group_id=release_group_id,
        release_id=release_id,
        format=format,
        preview=preview,
        include_deep_dependencies=include_deep_dependencies,
        include_direct_dependencies=include_direct_dependencies,
        include_fossa_dependencies=include_fossa_dependencies,
        include_license_list=include_license_list,
        include_license_scan=include_license_scan,
        include_project_license=include_project_license,
        include_copyright_list=include_copyright_list,
        include_file_matches=include_file_matches,
        include_open_vulnerabilities=include_open_vulnerabilities,
        include_closed_vulnerabilities=include_closed_vulnerabilities,
        include_dependency_summary=include_dependency_summary,
        include_license_headers=include_license_headers,
        include_package_labels=include_package_labels,
        dependency_info_options=dependency_info_options,
        exclude_package_labels=exclude_package_labels,
        release_group_title=release_group_title,
        release_title=release_title,
        release_group_url=release_group_url,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    # Exactly one of preview/download, so the endpoint always answers
    # synchronously and never falls through to the queued-job branch.
    params: list[tuple[str, str]] = [
        ("preview", bool_to_str(validated.preview)),
        ("download", bool_to_str(not validated.preview)),
    ]
    params.extend(_attribution_option_params(validated))
    params.append(("includePackageLabels", bool_to_str(validated.include_package_labels)))

    if validated.release_group_title is not None:
        params.append(("projectGroupTitle", validated.release_group_title))
    if validated.release_title is not None:
        params.append(("projectGroupReleaseTitle", validated.release_title))
    if validated.release_group_url is not None:
        params.append(("projectGroupUrl", validated.release_group_url))

    for option in validated.dependency_info_options or []:
        params.append(("dependencyInfoOptions[]", option))

    # FOSSA parses this query string with `qs`, so the exclusion array is sent
    # with bracket-and-index notation rather than repeated bare keys.
    for index, label in enumerate(validated.exclude_package_labels or []):
        params.append((f"excludeFields[packageLabels][{index}]", label))

    path = (
        f"/v2/project_group/{validated.release_group_id}"
        f"/release/{validated.release_id}/attribution/{validated.format}"
    )
    content, content_type = await client.request_text("GET", path, params=params)

    original_char_count = len(content)
    truncated = original_char_count > settings.fossa_report_max_chars
    display_text = content[: settings.fossa_report_max_chars] if truncated else content

    if validated.format in _TEXT_REPORT_FORMATS:
        content_value: Any = display_text
        json_parse_error = False
    else:
        try:
            content_value = json.loads(display_text)
            json_parse_error = False
        except json.JSONDecodeError:
            content_value = display_text
            json_parse_error = True

    # Same shape as fossa_get_attribution_report: report content sits at the top
    # level rather than under `data`.
    result: dict[str, Any] = {
        "ok": True,
        "endpoint": "GET /v2/project_group/{groupId}/release/{releaseId}/attribution/{format}",
        "format": validated.format,
        "content_type": content_type,
        "truncated": truncated,
        "content": content_value,
    }
    if truncated:
        result["original_char_count"] = original_char_count
    if json_parse_error:
        result["json_parse_error"] = True

    return result


async def get_release_group_attribution_status(
    ctx: Context,
    task_id: int,
) -> dict[str, Any]:
    """
    Check whether a queued release group attribution report has finished.

    Read-only. `task_id` is the value returned by
    fossa_queue_release_group_attribution_report. The response carries a status
    of CREATED, ASSIGNED, RUNNING, SUCCEEDED, or FAILED, plus a download URL once
    it has succeeded.
    """
    validated = AttributionTaskStatusInput(task_id=task_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    result = await client.request_json("GET", f"/project_group/attribution/{validated.task_id}")

    return {"ok": True, "endpoint": "GET /project_group/attribution/{taskId}", "data": result}


# --- writes ------------------------------------------------------------------


async def create_release_group(
    ctx: Context,
    title: str,
    release_title: str,
    projects: list[dict[str, str]],
    licensing_policy_id: int | None = None,
    security_policy_id: int | None = None,
    quality_policy_id: int | None = None,
    public_on_portal: bool | None = None,
    team_ids: list[int] | None = None,
) -> dict[str, Any]:
    """
    Create a FOSSA release group together with its first release.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    FOSSA has no empty release group, so the first release and its projects are
    part of the same call. Each entry in `projects` is an object with the keys
    `projectId` (a FOSSA project locator such as `git+github.com/acme/widget`),
    and optionally `branch` and `revisionId`. The call fails if the organization
    is already at its release group limit.
    """
    validated = ReleaseGroupCreateInput(
        title=title,
        release_title=release_title,
        projects=_release_projects(projects),
        licensing_policy_id=licensing_policy_id,
        security_policy_id=security_policy_id,
        quality_policy_id=quality_policy_id,
        public_on_portal=public_on_portal,
        team_ids=team_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_release_group")

    payload: dict[str, Any] = {
        "title": validated.title,
        "release": {
            "title": validated.release_title,
            "projects": _dump_projects(validated.projects),
        },
    }
    if validated.licensing_policy_id is not None:
        payload["licensingPolicyId"] = validated.licensing_policy_id
    if validated.security_policy_id is not None:
        payload["securityPolicyId"] = validated.security_policy_id
    if validated.quality_policy_id is not None:
        payload["qualityPolicyId"] = validated.quality_policy_id
    if validated.public_on_portal is not None:
        payload["publicOnPortal"] = validated.public_on_portal
    if validated.team_ids is not None:
        payload["teams"] = validated.team_ids

    result = await client.request_json("POST", "/project_group", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /project_group",
        "data": {"applied": payload, "release_group": result},
    }


async def update_release_group(
    ctx: Context,
    release_group_id: int,
    title: str | None = None,
    licensing_policy_id: int | None = None,
    security_policy_id: int | None = None,
    quality_policy_id: int | None = None,
    public_on_portal: bool | None = None,
    report_custom_text: str | None = None,
    clear_fields: list[ReleaseGroupClearableField] | None = None,
) -> dict[str, Any]:
    """
    Update a FOSSA release group's title, policies, portal visibility, or report
    text.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Only the fields passed are sent; anything omitted is left as FOSSA has it.
    Because an omitted argument and an explicit null look the same in a tool
    call, unsetting a nullable field is a separate list: naming a field in
    `clear_fields` sends null for it. Setting and clearing the same field in one
    call is rejected. This does not touch releases; use
    fossa_update_release_group_release for those.
    """
    validated = ReleaseGroupUpdateInput(
        release_group_id=release_group_id,
        title=title,
        licensing_policy_id=licensing_policy_id,
        security_policy_id=security_policy_id,
        quality_policy_id=quality_policy_id,
        public_on_portal=public_on_portal,
        report_custom_text=report_custom_text,
        clear_fields=clear_fields,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_update_release_group")

    payload: dict[str, Any] = {}
    if validated.title is not None:
        payload["title"] = validated.title
    if validated.licensing_policy_id is not None:
        payload["licensingPolicyId"] = validated.licensing_policy_id
    if validated.security_policy_id is not None:
        payload["securityPolicyId"] = validated.security_policy_id
    if validated.quality_policy_id is not None:
        payload["qualityPolicyId"] = validated.quality_policy_id
    if validated.public_on_portal is not None:
        payload["publicOnPortal"] = validated.public_on_portal
    if validated.report_custom_text is not None:
        payload["reportCustomText"] = validated.report_custom_text
    for field in validated.clear_fields or []:
        payload[field] = None

    result = await client.request_json(
        "PUT", f"/project_group/{validated.release_group_id}", json_body=payload
    )

    return {
        "ok": True,
        "endpoint": "PUT /project_group/{groupId}",
        "data": {"applied": payload, "release_group": result},
    }


async def delete_release_group(
    ctx: Context,
    release_group_id: int,
) -> dict[str, Any]:
    """
    Delete a FOSSA release group and every release in it.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    This removes the grouping, not the projects: the projects and their scan
    history survive. The release group and its releases do not, and FOSSA offers
    no undo. To remove one release instead, use
    fossa_delete_release_group_release.
    """
    validated = ReleaseGroupDeleteInput(release_group_id=release_group_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_release_group")

    # FOSSA answers the deletes in this domain with an empty body, so the text
    # form is used rather than request_json, which would report the empty body
    # as invalid JSON.
    await client.request_text("DELETE", f"/project_group/{validated.release_group_id}")

    return {
        "ok": True,
        "endpoint": "DELETE /project_group/{groupId}",
        "data": {"release_group_id": validated.release_group_id, "deleted": True},
    }


async def create_release_group_release(
    ctx: Context,
    release_group_id: int,
    title: str,
    projects: list[dict[str, str]],
) -> dict[str, Any]:
    """
    Add a release to an existing FOSSA release group.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Each entry in `projects` is an object with the keys `projectId` (a FOSSA
    project locator), and optionally `branch` and `revisionId`. A release with
    no projects reports nothing, so at least one is required.
    """
    validated = ReleaseCreateInput(
        release_group_id=release_group_id,
        title=title,
        projects=_release_projects(projects),
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_release_group_release")

    payload: dict[str, Any] = {
        "title": validated.title,
        "projects": _dump_projects(validated.projects),
    }

    result = await client.request_json(
        "POST", f"/project_group/{validated.release_group_id}/release", json_body=payload
    )

    return {
        "ok": True,
        "endpoint": "POST /project_group/{groupId}/release",
        "data": {"applied": payload, "release": result},
    }


async def update_release_group_release(
    ctx: Context,
    release_group_id: int,
    release_id: int,
    title: str,
    projects: list[dict[str, str]] | None = None,
    projects_to_delete: list[str] | None = None,
) -> dict[str, Any]:
    """
    Rename a release in a FOSSA release group and add, repin, or remove the
    projects in it.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    FOSSA requires `title` on this endpoint even when only the project list is
    changing; pass the release's current title to leave it as it is. Entries in
    `projects` are added or repinned, and each is an object with the keys
    `projectId`, and optionally `branch` and `revisionId`. `projects_to_delete`
    is a list of project locators to drop from the release. Naming the same
    project in both is rejected.
    """
    validated = ReleaseUpdateInput(
        release_group_id=release_group_id,
        release_id=release_id,
        title=title,
        projects=_release_projects(projects) if projects is not None else None,
        projects_to_delete=projects_to_delete,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_update_release_group_release")

    payload: dict[str, Any] = {"title": validated.title}
    if validated.projects is not None:
        payload["projects"] = _dump_projects(validated.projects)
    if validated.projects_to_delete is not None:
        payload["projectsToDelete"] = validated.projects_to_delete

    result = await client.request_json(
        "PUT",
        f"/project_group/{validated.release_group_id}/release/{validated.release_id}",
        json_body=payload,
    )

    return {
        "ok": True,
        "endpoint": "PUT /project_group/{groupId}/release/{projectGroupReleaseId}",
        "data": {"applied": payload, "release": result},
    }


async def delete_release_group_release(
    ctx: Context,
    release_group_id: int,
    release_id: int,
) -> dict[str, Any]:
    """
    Delete one release from a FOSSA release group.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The release group and its other releases are left alone, as are the projects
    the release pinned. FOSSA offers no undo.
    """
    validated = ReleaseDeleteInput(release_group_id=release_group_id, release_id=release_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_release_group_release")

    await client.request_text(
        "DELETE", f"/project_group/{validated.release_group_id}/release/{validated.release_id}"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /project_group/{groupId}/release/{projectGroupReleaseId}",
        "data": {
            "release_group_id": validated.release_group_id,
            "release_id": validated.release_id,
            "deleted": True,
        },
    }


async def queue_release_group_attribution_report(
    ctx: Context,
    release_group_id: int,
    release_id: int,
    format: ReleaseGroupReportFormat = "MD",
    is_publishing: bool = False,
    include_deep_dependencies: bool = True,
    include_direct_dependencies: bool = True,
    include_fossa_dependencies: bool = False,
    include_license_list: bool = True,
    include_license_scan: bool = False,
    include_project_license: bool = True,
    include_copyright_list: bool = False,
    include_file_matches: bool = False,
    include_open_vulnerabilities: bool = False,
    include_closed_vulnerabilities: bool = False,
    include_dependency_summary: bool = True,
    include_license_headers: bool = False,
    dependency_info_options: list[AttributionDependencyInfoOption] | None = None,
) -> dict[str, Any]:
    """
    Queue an attribution or SBOM report for one release in a FOSSA release group
    as a background job, and optionally publish it to the SBOM portal.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This is gated because it creates a job on FOSSA's side and, with
    `is_publishing` set, makes the report visible on the organization's SBOM
    portal. It returns a task id; poll it with
    fossa_get_release_group_attribution_status. For a report you just want to
    read, fossa_get_release_group_attribution_report returns the content
    directly and writes nothing.
    """
    validated = ReleaseGroupAttributionQueueInput(
        release_group_id=release_group_id,
        release_id=release_id,
        format=format,
        is_publishing=is_publishing,
        include_deep_dependencies=include_deep_dependencies,
        include_direct_dependencies=include_direct_dependencies,
        include_fossa_dependencies=include_fossa_dependencies,
        include_license_list=include_license_list,
        include_license_scan=include_license_scan,
        include_project_license=include_project_license,
        include_copyright_list=include_copyright_list,
        include_file_matches=include_file_matches,
        include_open_vulnerabilities=include_open_vulnerabilities,
        include_closed_vulnerabilities=include_closed_vulnerabilities,
        include_dependency_summary=include_dependency_summary,
        include_license_headers=include_license_headers,
        dependency_info_options=dependency_info_options,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_queue_release_group_attribution_report")

    params: list[tuple[str, str]] = list(_attribution_option_params(validated))
    params.append(("isPublishing", bool_to_str(validated.is_publishing)))
    for option in validated.dependency_info_options or []:
        params.append(("dependencyInfoOptions[]", option))

    path = (
        f"/project_group/{validated.release_group_id}"
        f"/release/{validated.release_id}/attribution/{validated.format}"
    )
    result = await client.request_json("POST", path, params=params)

    return {
        "ok": True,
        "endpoint": "POST /project_group/{groupId}/release/{releaseId}/attribution/{format}",
        "data": {
            "release_group_id": validated.release_group_id,
            "release_id": validated.release_id,
            "format": validated.format,
            "is_publishing": validated.is_publishing,
            "task": result,
        },
    }


# --- helpers -----------------------------------------------------------------


def _endpoint_list(template: str, suffixes: dict[str, str], sections: Sequence[str]) -> str:
    """Report every endpoint a sectioned read actually called, in call order."""
    return ", ".join(f"GET {template}{suffixes[section]}" for section in sections)


def _release_projects(projects: list[dict[str, str]]) -> list[ReleaseProject]:
    """Validate the raw project entries a tool received into `ReleaseProject`s.

    The tool signature takes plain objects so FastMCP builds the schema from the
    signature alone; the strictness (`projectId` required, unknown keys
    rejected) lives here.
    """
    return [ReleaseProject.model_validate(project) for project in projects]


def _dump_projects(projects: list[ReleaseProject]) -> list[dict[str, Any]]:
    """Render validated projects as FOSSA body objects, omitting unset keys."""
    return [project.model_dump(exclude_none=True) for project in projects]


def _attribution_option_params(options: AttributionOptions) -> list[tuple[str, str]]:
    """Build the report content switches both attribution endpoints share.

    Every switch is sent explicitly rather than relying on FOSSA's defaults, so
    the same tool call produces the same report regardless of which endpoint
    version is behind it.
    """
    return [
        ("includeDeepDependencies", bool_to_str(options.include_deep_dependencies)),
        ("includeDirectDependencies", bool_to_str(options.include_direct_dependencies)),
        ("includeFOSSADependencies", bool_to_str(options.include_fossa_dependencies)),
        ("includeLicenseList", bool_to_str(options.include_license_list)),
        ("includeLicenseScan", bool_to_str(options.include_license_scan)),
        ("includeProjectLicense", bool_to_str(options.include_project_license)),
        ("includeCopyrightList", bool_to_str(options.include_copyright_list)),
        ("includeFileMatches", bool_to_str(options.include_file_matches)),
        ("includeOpenVulnerabilities", bool_to_str(options.include_open_vulnerabilities)),
        ("includeClosedVulnerabilities", bool_to_str(options.include_closed_vulnerabilities)),
        ("includeDependencySummary", bool_to_str(options.include_dependency_summary)),
        ("includeLicenseHeaders", bool_to_str(options.include_license_headers)),
    ]
