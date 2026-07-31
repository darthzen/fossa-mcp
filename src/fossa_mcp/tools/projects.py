"""Project-related tools for the FOSSA MCP server.

Reads are ungated. `update_project` is `WRITE`; the two deletes and the
attribution-slug delete are `DESTRUCTIVE`. `apply_project_label` writes to a set
of projects but, like `assign_security_policy_to_projects`, refuses to address
that set by filter, so it stays at `WRITE`.

Two things about this domain are worth stating once here rather than in every
docstring:

* **Response bodies are largely undocumented.** `GET /projects/{locator}` and
  `PUT /projects/{locator}` both declare a bare `object` in the spec. Fields
  like `securityPolicyId` and `securityIssueScanningEnabled` were confirmed
  against a live organization, not read out of the spec. Every tool here passes
  FOSSA's JSON through unmodified rather than modeling it.
* **The query-string bulk endpoints take `locators[]`, not plain `locators`.**
  This was verified against a live organization on every one of them. The
  server parses its query string with `qs` and its schema demands an array (or
  the literal `"all"`): one plain `locators=<x>` parses as a *string* and is
  rejected with `400 "expected array, received string"`, while two or more
  parse as an array and happen to work. The bracketed form is an array at any
  length, so it is the only form that is correct for a one-project call. The
  spec's plain parameter name is a spec defect, not the wire format.

  `POST /v2/projects` is the exception and is not affected: it takes a JSON
  body, where the key is plain `locators` with a real array value — see
  `_project_filter_body`.
"""

from typing import Any
from urllib.parse import quote, urlencode

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import (
    InventoryType,
    IssueStatus,
    ProjectListInput,
    ProjectSort,
    ProjectType,
    RefType,
)
from ..models.projects import (
    ProjectAssociationSection,
    ProjectAssociationsInput,
    ProjectAttributionSlugInput,
    ProjectBulkDeleteInput,
    ProjectDeleteInput,
    ProjectExportFormat,
    ProjectIssueExportInput,
    ProjectLabelApplyInput,
    ProjectUpdateInput,
)
from ..query import add_repeated, bool_to_str
from ..writes import WriteTier, require_tier

# Above this many characters of query string, `list_projects` sends the same
# filters as a JSON body to POST /v2/projects instead. FOSSA documents that
# endpoint as the escape hatch for locator lists too long for a URL.
_MAX_QUERY_LENGTH = 1800


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

    Read-only. A `locators` filter long enough to overflow a URL is sent to
    FOSSA's equivalent POST endpoint instead; the result is the same.
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

    if len(urlencode(params)) > _MAX_QUERY_LENGTH:
        body = _project_filter_body(validated)
        result = await client.request_json("POST", "/v2/projects", json_body=body)
        return {"ok": True, "endpoint": "POST /v2/projects", "data": result}

    result = await client.request_json("GET", "/v2/projects", params=params)

    return {"ok": True, "endpoint": "GET /v2/projects", "data": result}


def _project_filter_body(validated: ProjectListInput) -> dict[str, Any]:
    """Render the same filters as the body POST /v2/projects expects.

    The body uses unbracketed, natively typed keys: `type` rather than `type[]`,
    a JSON boolean rather than the string `"true"`.
    """
    body: dict[str, Any] = {"page": validated.page, "count": validated.count}

    if validated.title is not None:
        body["title"] = validated.title
    if validated.types:
        body["type"] = list(validated.types)
    if validated.labels:
        body["labels"] = list(validated.labels)
    if validated.team_ids:
        body["teamId"] = list(validated.team_ids)
    if validated.locators:
        body["locators"] = list(validated.locators)
    if validated.inventory:
        body["inventory"] = list(validated.inventory)
    if validated.is_public is not None:
        body["isPublic"] = validated.is_public
    if validated.latest_scan_days is not None:
        body["latestScan"] = validated.latest_scan_days
    if validated.last_revision_within_days is not None:
        body["lastRevisionWithin"] = validated.last_revision_within_days
    if validated.include_shared_projects is not None:
        body["includeSharedProjects"] = validated.include_shared_projects
    if validated.only_include_shared_projects is not None:
        body["onlyIncludeSharedProjects"] = validated.only_include_shared_projects
    if validated.sort is not None:
        body["sort"] = validated.sort

    return body


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


async def get_projects_summary(ctx: Context) -> dict[str, Any]:
    """
    Count the projects, shared projects, and release groups in the organization.

    Read-only. Use it for a size check before listing anything; it answers "how
    many" without paging through fossa_list_projects.
    """
    client: FossaClient = ctx.request_context.lifespan_context["client"]

    result = await client.request_json("GET", "/v2/projects/summary")

    return {"ok": True, "endpoint": "GET /v2/projects/summary", "data": result}


_ASSOCIATION_ENDPOINTS: dict[ProjectAssociationSection, str] = {
    "labels": "GET /projects/{locator}/labels",
    "release_groups": "GET /v2/projects/{locator}/release-groups",
    "last_published": "GET /projects/{locator}/last-published",
}


async def get_project_associations(
    ctx: Context,
    project_locator: str,
    sections: list[ProjectAssociationSection] | None = None,
) -> dict[str, Any]:
    """
    List a project's labels, its release-group memberships, and the timestamp of
    the last update published for it.

    Read-only. All three sections are fetched unless `sections` narrows it, and
    each section is one FOSSA call. `last_published` comes back as a bare ISO
    timestamp string.
    """
    validated = ProjectAssociationsInput(project_locator=project_locator, sections=sections)

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    encoded_locator = quote(validated.project_locator, safe="")
    requested = validated.requested_sections()

    data: dict[str, Any] = {}
    for section in requested:
        if section == "labels":
            data["labels"] = await client.request_json("GET", f"/projects/{encoded_locator}/labels")
        elif section == "release_groups":
            data["release_groups"] = await client.request_json(
                "GET", f"/v2/projects/{encoded_locator}/release-groups"
            )
        else:
            data["last_published"] = await client.request_json(
                "GET", f"/projects/{encoded_locator}/last-published"
            )

    return {
        "ok": True,
        "endpoint": " + ".join(_ASSOCIATION_ENDPOINTS[section] for section in requested),
        "data": data,
    }


async def export_project_issues(
    ctx: Context,
    project_locator: str,
    format: ProjectExportFormat = "json",
    revision_id: str | None = None,
    status: IssueStatus | None = None,
    ref: str | None = None,
    ref_type: RefType | None = None,
) -> dict[str, Any]:
    """
    Export every issue on a project revision as one JSON or CSV document.

    Read-only. This is the whole-project export FOSSA's UI offers, grouped by
    issue type; use fossa_list_issues instead when the caller wants filtered,
    paged issues rather than a report. Without `revision_id` or `ref` the latest
    revision on the default branch is exported. CSV is returned as raw text
    under `data.content`.
    """
    validated = ProjectIssueExportInput(
        project_locator=project_locator,
        format=format,
        revision_id=revision_id,
        status=status,
        ref=ref,
        ref_type=ref_type,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = []
    if validated.revision_id is not None:
        params.append(("revisionId", validated.revision_id))
    if validated.status is not None:
        params.append(("status", validated.status))
    if validated.ref is not None:
        params.append(("ref", validated.ref))
        # Same snake_case key as getProject; `refType` is silently ignored.
        params.append(("ref_type", validated.ref_type or "branch"))

    encoded_locator = quote(validated.project_locator, safe="")
    path = f"/projects/{encoded_locator}/export-issues/{validated.format}"
    endpoint = f"GET /projects/{{locator}}/export-issues/{validated.format}"

    if validated.format == "csv":
        content, content_type = await client.request_text("GET", path, params=params)
        return {
            "ok": True,
            "endpoint": endpoint,
            "data": {"format": "csv", "content_type": content_type, "content": content},
        }

    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": endpoint, "data": result}


async def update_project(
    ctx: Context,
    project_locator: str,
    title: str | None = None,
    description: str | None = None,
    project_url: str | None = None,
    notes: str | None = None,
    public: bool | None = None,
    default_branch: str | None = None,
    tracking_branches: list[str] | None = None,
    hidden_branches: list[str] | None = None,
    policy_id: int | None = None,
    security_policy_id: int | None = None,
    quality_policy_id: int | None = None,
    sbom_policy_id: int | None = None,
    policies_approve_multilicense: bool | None = None,
    licensing_issue_scanning_enabled: bool | None = None,
    security_issue_scanning_enabled: bool | None = None,
    quality_issue_scanning_enabled: bool | None = None,
    sbom_analysis_enabled: bool | None = None,
    licensing_status_check_enabled: bool | None = None,
    security_status_check_enabled: bool | None = None,
    quality_status_check_enabled: bool | None = None,
    label_ids: list[int] | None = None,
    transitive_excludes: list[str] | None = None,
    report_custom_text: str | None = None,
) -> dict[str, Any]:
    """
    Update one project's settings: metadata, branches, policy assignments,
    scanning, CI status checks, labels, and ignored dependencies.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Every field defaults to None, meaning "leave unchanged" — only the fields
    named in the call are sent. Two of them replace rather than merge:
    `label_ids` replaces the project's whole label set, and
    `transitive_excludes` replaces the whole ignore list, so read the current
    value with fossa_get_project first if you mean to add to either.
    `tracking_branches` and `hidden_branches` are mutually exclusive.

    Changing a policy or a scanning setting makes FOSSA rescan the project.
    """
    validated = ProjectUpdateInput(
        project_locator=project_locator,
        title=title,
        description=description,
        project_url=project_url,
        notes=notes,
        public=public,
        default_branch=default_branch,
        tracking_branches=tracking_branches,
        hidden_branches=hidden_branches,
        policy_id=policy_id,
        security_policy_id=security_policy_id,
        quality_policy_id=quality_policy_id,
        sbom_policy_id=sbom_policy_id,
        policies_approve_multilicense=policies_approve_multilicense,
        licensing_issue_scanning_enabled=licensing_issue_scanning_enabled,
        security_issue_scanning_enabled=security_issue_scanning_enabled,
        quality_issue_scanning_enabled=quality_issue_scanning_enabled,
        sbom_analysis_enabled=sbom_analysis_enabled,
        licensing_status_check_enabled=licensing_status_check_enabled,
        security_status_check_enabled=security_status_check_enabled,
        quality_status_check_enabled=quality_status_check_enabled,
        label_ids=label_ids,
        transitive_excludes=transitive_excludes,
        report_custom_text=report_custom_text,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_update_project")

    payload = validated.to_payload()
    encoded_locator = quote(validated.project_locator, safe="")

    result = await client.request_json("PUT", f"/projects/{encoded_locator}", json_body=payload)

    return {
        "ok": True,
        "endpoint": "PUT /projects/{locator}",
        "data": {"applied": payload, "project": result},
    }


async def apply_project_label(
    ctx: Context,
    label_id: int,
    project_locators: list[str],
) -> dict[str, Any]:
    """
    Apply one existing organization label to a list of projects.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    `label_id` is a numeric id of a label that already exists in the
    organization; this does not create labels. Every target project must be
    named explicitly — the endpoint's "apply to all projects matching these
    filters" mode is deliberately not exposed. FOSSA answers with a map of the
    projects that failed, which is reported under `failures`.
    """
    validated = ProjectLabelApplyInput(label_id=label_id, project_locators=project_locators)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_apply_project_label")

    params: list[tuple[str, str]] = [("labelId", str(validated.label_id))]
    for locator in validated.project_locators:
        params.append(("locators[]", locator))

    result = await client.request_json("PUT", "/v2/projects/labels", params=params)

    failures = result if isinstance(result, dict) else {}

    return {
        "ok": True,
        "endpoint": "PUT /v2/projects/labels",
        "data": {
            "label_id": validated.label_id,
            "requested": validated.project_locators,
            "failures": failures,
            "succeeded": [
                locator for locator in validated.project_locators if locator not in failures
            ],
        },
    }


async def generate_project_attribution_slug(
    ctx: Context,
    project_locator: str,
) -> dict[str, Any]:
    """
    Create or regenerate the slug in the URL of a project's live attribution
    report.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Regenerating replaces the existing slug, which breaks any previously shared
    report link. FOSSA requires a Premium subscription for this endpoint and
    answers 403 without one. The response is the new slug as a bare JSON string.
    """
    validated = ProjectAttributionSlugInput(project_locator=project_locator)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_generate_project_attribution_slug")

    encoded_locator = quote(validated.project_locator, safe="")
    result = await client.request_json(
        "PUT", f"/projects/{encoded_locator}/generate_attribution_slug"
    )

    return {
        "ok": True,
        "endpoint": "PUT /projects/{locator}/generate_attribution_slug",
        "data": {"project_locator": validated.project_locator, "slug": result},
    }


async def delete_project_attribution_slug(
    ctx: Context,
    project_locator: str,
) -> dict[str, Any]:
    """
    Remove the slug from a project's live attribution report URL, which takes
    the shared report offline.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    Anyone holding the old link loses access. Only the slug is deleted; the
    project and its scan history are untouched.
    """
    validated = ProjectAttributionSlugInput(project_locator=project_locator)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_project_attribution_slug")

    encoded_locator = quote(validated.project_locator, safe="")
    # 204 with an empty body: request_json would fail parsing it.
    body, _ = await client.request_text(
        "DELETE", f"/projects/{encoded_locator}/generate_attribution_slug"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /projects/{locator}/generate_attribution_slug",
        "data": {"project_locator": validated.project_locator, "response": body or None},
    }


async def delete_project(
    ctx: Context,
    project_locator: str,
) -> dict[str, Any]:
    """
    Permanently delete one project and everything FOSSA has scanned for it.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    This cannot be undone: revisions, issues, and scan history go with the
    project. Confirm the exact locator with fossa_get_project first; a locator
    guessed from a repository name may name a different project.
    """
    validated = ProjectDeleteInput(project_locator=project_locator)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_project")

    encoded_locator = quote(validated.project_locator, safe="")
    # 200 with an empty body.
    body, _ = await client.request_text("DELETE", f"/projects/{encoded_locator}")

    return {
        "ok": True,
        "endpoint": "DELETE /projects/{locator}",
        "data": {"deleted": [validated.project_locator], "response": body or None},
    }


async def delete_projects(
    ctx: Context,
    project_locators: list[str],
) -> dict[str, Any]:
    """
    Permanently delete several named projects in one call.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    Every project must be named by locator. FOSSA's endpoint also accepts
    `locators=all`, which deletes every project matching a set of filters and,
    with no filters, every project in the organization; this tool does not
    expose that mode and no combination of arguments can reach it. Deletion
    cannot be undone.
    """
    validated = ProjectBulkDeleteInput(project_locators=project_locators)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_projects")

    # Locators only. No filter parameter is sent, so there is nothing for FOSSA
    # to widen the target set with.
    params: list[tuple[str, str]] = [
        ("locators[]", locator) for locator in validated.project_locators
    ]

    body, _ = await client.request_text("DELETE", "/v2/projects", params=params)

    return {
        "ok": True,
        "endpoint": "DELETE /v2/projects",
        "data": {"deleted": validated.project_locators, "response": body or None},
    }
