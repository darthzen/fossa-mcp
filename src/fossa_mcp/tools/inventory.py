"""Inventory long-tail tools for the FOSSA MCP server.

The domains here are almost entirely read surface — binary decomposition,
package observability, components, audit logs, SBOM sharing, license
conclusions, builds, vulnerability lookups, and the two organization capability
endpoints. They share no locator model with each other, so they are grouped by
what a FOSSA operator would go looking for rather than by URL prefix.

Four things about this module are load-bearing:

* **Binary and package tools are grouped behind a `Literal`.** `scope`, `view`,
  and `section` choose the endpoint. An unknown value fails as a schema error at
  the client; nothing here forwards a caller-supplied path fragment, so these
  stay explicit action tools rather than the generic proxy that DECISIONS.md §7
  rules out.
* **`GET /packages` and `GET /packages/report` serialize arrays with
  bracket-and-index notation** (`fetchers[0]=npm`), which is what their own spec
  examples show. The issue endpoints use a bare `[]` suffix and the audit log
  endpoints declare the `[]` in the parameter name itself. All three appear in
  this file; they are not interchangeable.
* **License conclusions are one tool with two verbs and a per-call tier.**
  `unconclude` removes state, so it is `DESTRUCTIVE` at every scope; `conclude`
  is `WRITE` unless the scope is org-wide, which makes its target set unbounded.
  See the tool docstring.
* **Two endpoints do not answer the way `request_json` expects.**
  `POST /components/build` documents a `201` with no body at all, and
  `GET /services/github-app/installation-url` documents only a `302` whose
  payload is the `Location` header. Both are spec gaps worth reporting upstream.
  Neither is worked around here: they go through `client.request_json_optional`
  and `client.request_redirect_location`, which is where transport behavior
  belongs.
"""

from collections.abc import Sequence
from datetime import date, datetime
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import Severity
from ..models.inventory import (
    AuditLogExportInput,
    AuditLogReadInput,
    AuditLogSortBy,
    AuditLogView,
    BinaryComponentsInput,
    BinaryComponentView,
    BinaryDependencyConfidenceInput,
    BinaryRevisionDetailInput,
    BinaryRevisionView,
    BinaryScope,
    BuildFileType,
    BuildReadInput,
    BuildView,
    ComponentBuildInput,
    ComponentUploadUrlInput,
    CveSearchInput,
    LicenseConclusionAction,
    LicenseConclusionInput,
    LicenseConclusionScope,
    PackageBlockType,
    PackageDepth,
    PackageFetcher,
    PackageFilters,
    PackageFixType,
    PackageIndexExportInput,
    PackageListInput,
    PackageObservabilityInput,
    PackageObservabilitySection,
    PackageSort,
    PackageVisibility,
    ResolvePurlsInput,
    SbomShareInput,
    SbomSharingReadInput,
    SbomSharingSection,
    SortDirection,
    UploadFileType,
    VulnerabilityRemediationInput,
)
from ..query import add_repeated, bool_to_str
from ..writes import WriteTier, require_tier

# --- shared helpers ----------------------------------------------------------


def _encode(value: str) -> str:
    """Percent-encode a locator for use as a single path segment.

    FOSSA locators carry `+`, `/`, and `$`, all of which change the path if left
    unescaped, so nothing is safe.
    """
    return quote(value, safe="")


def _add_indexed(
    params: list[tuple[str, str]],
    key: str,
    values: Sequence[str] | None,
) -> None:
    """Serialize an array filter as `key[0]=…&key[1]=…`.

    The package endpoints parse their query string with `qs` and document this
    form in their own parameter examples (`fetchers[0]=npm&fetchers[1]=apk`).
    The `[]`-suffixed form used elsewhere in this server does not reach them.
    """
    for index, value in enumerate(values or []):
        params.append((f"{key}[{index}]", value))


def _add_plain_repeated(
    params: list[tuple[str, str]],
    key: str,
    values: Sequence[str] | None,
) -> None:
    """Repeat a query key with no bracket suffix (OpenAPI `style: form`)."""
    for value in values or []:
        params.append((key, value))


# --- binary decomposition ----------------------------------------------------
#
# Every /binary endpoint sits behind FOSSA's `binaryDecomposition` feature flag.
# An organization without it gets a 403, not an empty result, so a failure here
# is usually entitlement rather than a bad locator.


async def binary_components(
    ctx: Context,
    scope: BinaryScope,
    view: BinaryComponentView = "count",
    revision_locator: str | None = None,
    release_group_id: int | None = None,
    release_id: int | None = None,
    path: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """
    Count the binary decomposition components found in a revision or a release
    group release, or list them grouped by the file path they were found at.

    Read-only. `scope` selects what is being asked about: "revision" needs
    revision_locator, "release" needs both release_group_id and release_id.
    `view="count"` returns a single total; `view="paths"` returns the directory
    tree, one level at a time, and is the only view that accepts `path` and
    `search`.
    """
    validated = BinaryComponentsInput(
        scope=scope,
        view=view,
        revision_locator=revision_locator,
        release_group_id=release_group_id,
        release_id=release_id,
        path=path,
        search=search,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    if validated.scope == "revision":
        assert validated.revision_locator is not None
        base = f"/binary/revision/{_encode(validated.revision_locator)}/components"
        endpoint = f"GET /binary/revision/{{revisionLocator}}/components/{validated.view}"
    else:
        base = (
            f"/binary/release-group/{validated.release_group_id}"
            f"/release/{validated.release_id}/components"
        )
        endpoint = (
            "GET /binary/release-group/{releaseGroupId}/release/{releaseId}"
            f"/components/{validated.view}"
        )

    params: list[tuple[str, str]] = []
    if validated.path is not None:
        params.append(("path", validated.path))
    if validated.search is not None:
        params.append(("search", validated.search))

    result = await client.request_json("GET", f"{base}/{validated.view}", params=params)

    return {"ok": True, "endpoint": endpoint, "data": result}


async def binary_dependency_confidence(
    ctx: Context,
    scope: BinaryScope,
    revision_locator: str | None = None,
    release_id: int | None = None,
    dependency_locator: str | None = None,
) -> dict[str, Any]:
    """
    Report how confident FOSSA is that each binary component it matched really
    is the dependency it named.

    Read-only. Returns a map of dependency locator to High, Medium, Low, or
    Unknown. Pass dependency_locator to ask about one dependency instead of all
    of them. "revision" scope needs revision_locator; "release" scope needs
    release_id.
    """
    validated = BinaryDependencyConfidenceInput(
        scope=scope,
        revision_locator=revision_locator,
        release_id=release_id,
        dependency_locator=dependency_locator,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    if validated.scope == "revision":
        assert validated.revision_locator is not None
        base = f"/binary/{_encode(validated.revision_locator)}/dependency-confidence"
        endpoint = "GET /binary/{revisionLocator}/dependency-confidence"
    else:
        base = f"/binary/release/{validated.release_id}/dependency-confidence"
        endpoint = "GET /binary/release/{releaseId}/dependency-confidence"

    if validated.dependency_locator is not None:
        base = f"{base}/{_encode(validated.dependency_locator)}"
        endpoint = f"{endpoint}/{{dependencyLocator}}"

    result = await client.request_json("GET", base)

    return {"ok": True, "endpoint": endpoint, "data": result}


async def binary_revision_detail(
    ctx: Context,
    view: BinaryRevisionView,
    revision_locator: str,
    component_id: str | None = None,
    dependency_locator: str | None = None,
    page: int = 1,
    page_size: int = 10,
) -> dict[str, Any]:
    """
    Drill into one binary decomposition revision: either the match strings that
    identified a component, or the components that make up a dependency.

    Read-only. "component_matches" needs component_id and returns the strings
    FOSSA matched with their hit counts. "dependency_components" needs
    dependency_locator and returns the component files attributed to it. Both
    are paginated, page_size capped at 50 by FOSSA.
    """
    validated = BinaryRevisionDetailInput(
        view=view,
        revision_locator=revision_locator,
        component_id=component_id,
        dependency_locator=dependency_locator,
        page=page,
        page_size=page_size,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    encoded_revision = _encode(validated.revision_locator)
    if validated.view == "component_matches":
        assert validated.component_id is not None
        path = f"/binary/{encoded_revision}/{_encode(validated.component_id)}/matches"
        endpoint = "GET /binary/{revisionLocator}/{componentId}/matches"
    else:
        assert validated.dependency_locator is not None
        path = f"/binary/{encoded_revision}/{_encode(validated.dependency_locator)}/components"
        endpoint = "GET /binary/{revisionLocator}/{dependencyLocator}/components"

    params: list[tuple[str, str]] = [
        ("page", str(validated.page)),
        ("pageSize", str(validated.page_size)),
    ]

    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": endpoint, "data": result}


# --- package observability ---------------------------------------------------


def _package_filter_params(validated: PackageFilters) -> list[tuple[str, str]]:
    """Serialize the fourteen filters shared by the two package index endpoints."""
    params: list[tuple[str, str]] = []
    _add_indexed(params, "fetchers", validated.fetchers)
    if validated.package_name is not None:
        params.append(("packageName", validated.package_name))
    _add_indexed(params, "depth", validated.depth)
    _add_indexed(params, "labels", validated.labels)
    if validated.project_name is not None:
        params.append(("projectName", validated.project_name))
    _add_indexed(params, "sources", validated.sources)
    _add_indexed(params, "visibility", validated.visibility)
    _add_indexed(params, "blockTypes", validated.block_types)
    if validated.cve is not None:
        params.append(("cve", validated.cve))
    _add_indexed(params, "cwes", validated.cwes)
    _add_indexed(params, "fixTypes", validated.fix_types)
    _add_indexed(params, "severities", validated.severities)
    _add_indexed(
        params,
        "teamIds",
        [str(team_id) for team_id in validated.team_ids or []] or None,
    )
    _add_indexed(params, "locators", validated.locators)
    return params


async def list_packages(
    ctx: Context,
    fetchers: list[PackageFetcher] | None = None,
    package_name: str | None = None,
    depth: list[PackageDepth] | None = None,
    labels: list[str] | None = None,
    project_name: str | None = None,
    sources: list[str] | None = None,
    visibility: list[PackageVisibility] | None = None,
    block_types: list[PackageBlockType] | None = None,
    cve: str | None = None,
    cwes: list[str] | None = None,
    fix_types: list[PackageFixType] | None = None,
    severities: list[Severity] | None = None,
    team_ids: list[int] | None = None,
    locators: list[str] | None = None,
    page: int = 1,
    count: int = 20,
    sort: PackageSort | None = None,
) -> dict[str, Any]:
    """
    List the third-party packages the organization depends on, with how many
    projects use each one and how many of its versions are blocked.

    Read-only. This is the organization-wide package view, not a per-project
    dependency list: use fossa_list_dependencies for one revision's tree. The
    filters answer "who still ships a package with this CVE" without walking
    every project.
    """
    validated = PackageListInput(
        fetchers=fetchers,
        package_name=package_name,
        depth=depth,
        labels=labels,
        project_name=project_name,
        sources=sources,
        visibility=visibility,
        block_types=block_types,
        cve=cve,
        cwes=cwes,
        fix_types=fix_types,
        severities=severities,
        team_ids=team_ids,
        locators=locators,
        page=page,
        count=count,
        sort=sort,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params = _package_filter_params(validated)
    params.append(("page", str(validated.page)))
    params.append(("count", str(validated.count)))
    if validated.sort is not None:
        params.append(("sort", validated.sort))

    result = await client.request_json("GET", "/packages", params=params)

    return {"ok": True, "endpoint": "GET /packages", "data": result}


_OBSERVABILITY_PATHS: dict[PackageObservabilitySection, str] = {
    "summary": "/packages/package-summary",
    "package_managers": "/packages/package-managers",
    "locators": "/packages/package-locators",
}


async def package_observability(
    ctx: Context,
    section: PackageObservabilitySection = "summary",
    package_locator: str | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    """
    Read the package index's own metadata: the total package count and when the
    index was last cached, the package managers in use, or a search over package
    locators.

    Read-only. "summary" and "package_managers" take no arguments;
    package_locator and count apply only to the "locators" section, where
    package_locator is a partial match and count is capped at 50.
    """
    validated = PackageObservabilityInput(
        section=section,
        package_locator=package_locator,
        count=count,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = []
    if validated.package_locator is not None:
        params.append(("packageLocator", validated.package_locator))
    if validated.count is not None:
        params.append(("count", str(validated.count)))

    path = _OBSERVABILITY_PATHS[validated.section]
    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {path}", "data": result}


async def export_package_index(
    ctx: Context,
    fetchers: list[PackageFetcher] | None = None,
    package_name: str | None = None,
    depth: list[PackageDepth] | None = None,
    labels: list[str] | None = None,
    project_name: str | None = None,
    sources: list[str] | None = None,
    visibility: list[PackageVisibility] | None = None,
    block_types: list[PackageBlockType] | None = None,
    cve: str | None = None,
    cwes: list[str] | None = None,
    fix_types: list[PackageFixType] | None = None,
    severities: list[Severity] | None = None,
    team_ids: list[int] | None = None,
    locators: list[str] | None = None,
) -> dict[str, Any]:
    """
    Queue an export of the package index and have FOSSA email the download link
    to the calling token's user.

    Read-only with respect to FOSSA state, and a GET, but it does send mail: the
    organization's package inventory leaves FOSSA as a link in someone's inbox.
    Nothing is returned but the background task reference; this server has no
    endpoint to poll it. Use fossa_list_packages to see the same rows inline.
    """
    validated = PackageIndexExportInput(
        fetchers=fetchers,
        package_name=package_name,
        depth=depth,
        labels=labels,
        project_name=project_name,
        sources=sources,
        visibility=visibility,
        block_types=block_types,
        cve=cve,
        cwes=cwes,
        fix_types=fix_types,
        severities=severities,
        team_ids=team_ids,
        locators=locators,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    result = await client.request_json(
        "GET", "/packages/report", params=_package_filter_params(validated)
    )

    return {"ok": True, "endpoint": "GET /packages/report", "data": result}


# --- components --------------------------------------------------------------


async def get_component_upload_url(
    ctx: Context,
    package_spec: str,
    revision: str,
    file_type: UploadFileType | None = None,
) -> dict[str, Any]:
    """
    Get a pre-signed URL for uploading a component archive, SBOM, or binary to
    FOSSA. The URL expires in five minutes.

    Read-only: this mints an upload URL, it does not upload anything. This
    server cannot perform the upload either — the returned URL has to be PUT to
    by whoever holds the file. Call fossa_build_component afterwards to start
    the analysis. file_type="binary" is billing-gated and 403s when the
    organization is out of binary decompositions.
    """
    validated = ComponentUploadUrlInput(
        package_spec=package_spec,
        revision=revision,
        file_type=file_type,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = [
        ("packageSpec", validated.package_spec),
        ("revision", validated.revision),
    ]
    if validated.file_type is not None:
        params.append(("fileType", validated.file_type))

    result = await client.request_json("GET", "/components/signed_url", params=params)

    return {"ok": True, "endpoint": "GET /components/signed_url", "data": result}


async def resolve_purls(
    ctx: Context,
    purls: list[str],
) -> dict[str, Any]:
    """
    Resolve up to 100 package URLs to the FOSSA components they identify and
    return the licensing FOSSA holds for each.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    The read is the point, but a PURL FOSSA has not analyzed yet is queued for
    an asynchronous build, which creates work in the organization — so it is
    gated like any other POST. Each result comes back as "success" with
    licensing, "queued" if a build was needed, or "error"; call again later for
    the queued ones.
    """
    validated = ResolvePurlsInput(purls=purls)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_resolve_purls")

    body: dict[str, Any] = {"purls": validated.purls}
    result = await client.request_json("POST", "/components/resolve-purls", json_body=body)

    return {
        "ok": True,
        "endpoint": "POST /components/resolve-purls",
        "data": {"requested": validated.purls, "results": result},
    }


async def build_component(
    ctx: Context,
    package_spec: str,
    revision: str,
    file_type: BuildFileType | None = None,
    dependency: bool | None = None,
    description: str | None = None,
    branch: str | None = None,
    jira_project_key: str | None = None,
    link: str | None = None,
    project_url: str | None = None,
    policy: str | None = None,
    policy_id: int | None = None,
    team: str | None = None,
    title: str | None = None,
    release_group: str | None = None,
    release_group_release: str | None = None,
    labels: list[str] | None = None,
    selected_team_ids: list[int] | None = None,
    selected_team_names: list[str] | None = None,
    force_rebuild: bool | None = None,
) -> dict[str, Any]:
    """
    Start an asynchronous build of a component that was already uploaded to a
    signed URL.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This creates a project and a revision in the organization, assigns the
    policy, team, labels, and release group given, and queues analysis. Get the
    upload URL from fossa_get_component_upload_url first and PUT the file to it;
    this tool only starts the build. Non-premium organizations may only import
    SBOMs. force_rebuild re-analyzes a revision FOSSA has already built.
    """
    validated = ComponentBuildInput(
        package_spec=package_spec,
        revision=revision,
        file_type=file_type,
        dependency=dependency,
        description=description,
        branch=branch,
        jira_project_key=jira_project_key,
        link=link,
        project_url=project_url,
        policy=policy,
        policy_id=policy_id,
        team=team,
        title=title,
        release_group=release_group,
        release_group_release=release_group_release,
        labels=labels,
        selected_team_ids=selected_team_ids,
        selected_team_names=selected_team_names,
        force_rebuild=force_rebuild,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_build_component")

    params: list[tuple[str, str]] = [
        ("packageSpec", validated.package_spec),
        ("revision", validated.revision),
    ]
    if validated.dependency is not None:
        params.append(("dependency", bool_to_str(validated.dependency)))
    if validated.description is not None:
        params.append(("description", validated.description))
    if validated.file_type is not None:
        params.append(("fileType", validated.file_type))
    if validated.branch is not None:
        params.append(("branch", validated.branch))
    if validated.jira_project_key is not None:
        params.append(("jiraProjectKey", validated.jira_project_key))
    if validated.link is not None:
        params.append(("link", validated.link))
    if validated.project_url is not None:
        params.append(("projectURL", validated.project_url))
    if validated.policy is not None:
        params.append(("policy", validated.policy))
    if validated.policy_id is not None:
        params.append(("policyId", str(validated.policy_id)))
    if validated.team is not None:
        params.append(("team", validated.team))
    if validated.title is not None:
        params.append(("title", validated.title))
    if validated.release_group is not None:
        params.append(("releaseGroup", validated.release_group))
    if validated.release_group_release is not None:
        params.append(("releaseGroupRelease", validated.release_group_release))
    # `labels` is declared `style: form` with the default explode, so it goes
    # over the wire as a repeated bare key rather than a bracketed array.
    _add_plain_repeated(params, "labels", validated.labels)

    body = validated.to_body()

    # The documented 201 is bare "Created" with no content schema.
    result = await client.request_json_optional(
        "POST", "/components/build", params=params, json_body=body
    )

    return {
        "ok": True,
        "endpoint": "POST /components/build",
        "data": {"applied": body, "result": result},
    }


# --- audit logs --------------------------------------------------------------

_AUDIT_LOG_PATHS: dict[AuditLogView, str] = {
    "list": "/audit_logs",
    "count": "/count/audit_logs",
}


async def get_audit_logs(
    ctx: Context,
    view: AuditLogView = "list",
    offset: int | None = None,
    limit: int | None = None,
    sort_by: AuditLogSortBy | None = None,
    sort_dir: SortDirection | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    acting_user_ids: list[str] | None = None,
    actions: list[str] | None = None,
    topics: list[str] | None = None,
    topic_actions: list[str] | None = None,
    starting_after: str | None = None,
    ending_before: str | None = None,
) -> dict[str, Any]:
    """
    Read the organization's audit log, or just count the entries matching a
    filter.

    Read-only. Every entry records who acted, on what, and the old and new
    value. Both views take the same filters, so run view="count" first to size a
    query before paging it. starting_after is a row-id cursor and is the
    reliable way to page a live log; offset drifts as entries arrive.
    """
    validated = AuditLogReadInput(
        view=view,
        offset=offset,
        limit=limit,
        sort_by=sort_by,
        sort_dir=sort_dir,
        start_date=start_date,
        end_date=end_date,
        acting_user_ids=acting_user_ids,
        actions=actions,
        topics=topics,
        topic_actions=topic_actions,
        starting_after=starting_after,
        ending_before=ending_before,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = []
    if validated.offset is not None:
        params.append(("offset", str(validated.offset)))
    if validated.limit is not None:
        params.append(("limit", str(validated.limit)))
    if validated.sort_by is not None:
        params.append(("sortBy", validated.sort_by))
    if validated.sort_dir is not None:
        params.append(("sortDir", validated.sort_dir))
    if validated.start_date is not None:
        params.append(("startDate", validated.start_date.isoformat()))
    if validated.end_date is not None:
        params.append(("endDate", validated.end_date.isoformat()))
    # These four declare the `[]` in the parameter name itself, which is what
    # `add_repeated` appends.
    add_repeated(params, "actingUserIds", validated.acting_user_ids)
    add_repeated(params, "actions", validated.actions)
    add_repeated(params, "topics", validated.topics)
    add_repeated(params, "topicActions", validated.topic_actions)
    if validated.starting_after is not None:
        params.append(("startingAfter", validated.starting_after))
    if validated.ending_before is not None:
        params.append(("endingBefore", validated.ending_before))

    path = _AUDIT_LOG_PATHS[validated.view]
    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {path}", "data": result}


async def export_audit_logs(
    ctx: Context,
    start_date: date,
    end_date: date,
    acting_user_ids: list[str] | None = None,
    actions: list[str] | None = None,
    topics: list[str] | None = None,
    topic_actions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Queue a CSV export of the audit log for a date range and have FOSSA email
    the download link to the calling token's user.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    No audit entry changes, but this creates a background job and mails the
    organization's audit history out, so it is gated like any other POST. Dates
    are YYYY-MM-DD and both are required. Requires a premium FOSSA subscription.
    """
    validated = AuditLogExportInput(
        start_date=start_date,
        end_date=end_date,
        acting_user_ids=acting_user_ids,
        actions=actions,
        topics=topics,
        topic_actions=topic_actions,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_export_audit_logs")

    body: dict[str, Any] = {
        "startDate": validated.start_date.isoformat(),
        "endDate": validated.end_date.isoformat(),
    }
    if validated.acting_user_ids is not None:
        body["actingUserIds"] = validated.acting_user_ids
    if validated.actions is not None:
        body["actions"] = validated.actions
    if validated.topics is not None:
        body["topics"] = validated.topics
    if validated.topic_actions is not None:
        body["topicActions"] = validated.topic_actions

    result = await client.request_json("POST", "/audit_logs/export", json_body=body)

    return {
        "ok": True,
        "endpoint": "POST /audit_logs/export",
        "data": {"applied": body, "task": result},
    }


# --- SBOM sharing ------------------------------------------------------------

_SBOM_SHARING_PATHS: dict[SbomSharingSection, str] = {
    "share_requests": "/v1/share-requests",
    "linked_organizations": "/v1/shared-organizations",
}


async def get_sbom_sharing(
    ctx: Context,
    section: SbomSharingSection = "share_requests",
    project_locator: str | None = None,
) -> dict[str, Any]:
    """
    List the SBOM revisions this organization has shared with others, or the
    organizations it is linked to for SBOM sharing.

    Read-only. "share_requests" is what went out and to whom, optionally
    filtered to one project; "linked_organizations" is the two-sided list of who
    this organization may share with and who has shared with it. The
    sharedOrganizationId in that list is what fossa_share_sbom_revision needs.
    """
    validated = SbomSharingReadInput(section=section, project_locator=project_locator)

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = []
    if validated.project_locator is not None:
        params.append(("projectLocator", validated.project_locator))

    path = _SBOM_SHARING_PATHS[validated.section]
    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {path}", "data": result}


async def share_sbom_revision(
    ctx: Context,
    revision_id: str,
    shared_organization_id: int,
) -> dict[str, Any]:
    """
    Share one SBOM project revision with another organization.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This discloses the revision's contents to a different organization and the
    vendored spec documents no endpoint to withdraw it, so treat it as one-way.
    shared_organization_id is the id of an existing link, not an organization id
    — read it from fossa_get_sbom_sharing(section="linked_organizations"). Only
    revisions of SBOM projects can be shared, and the organization needs the
    sbomSharing feature flag.
    """
    validated = SbomShareInput(
        revision_id=revision_id,
        shared_organization_id=shared_organization_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_share_sbom_revision")

    body: dict[str, Any] = {
        "revisionId": validated.revision_id,
        "sharedOrganizationId": validated.shared_organization_id,
    }

    result = await client.request_json("POST", "/v1/share-requests", json_body=body)

    return {
        "ok": True,
        "endpoint": "POST /v1/share-requests",
        "data": {"applied": body, "task": result},
    }


# --- license conclusions -----------------------------------------------------

_LICENSE_CONCLUSION_PATHS: dict[LicenseConclusionAction, str] = {
    "conclude": "/license-conclusions/conclude",
    "unconclude": "/license-conclusions/unconclude",
}


async def set_license_conclusion(
    ctx: Context,
    action: LicenseConclusionAction,
    dependency_revision_locator: str,
    scope: LicenseConclusionScope,
    license_id: str,
    project_locator: str | None = None,
    revision_locator: str | None = None,
    release_group_id: int | None = None,
    release_id: int | None = None,
    organization_id: int | None = None,
    origin_id: str | None = None,
) -> dict[str, Any]:
    """
    Add a license to, or remove one from, the concluded licenses FOSSA reports
    for a dependency revision.

    WRITES TO FOSSA. action="conclude" requires FOSSA_ALLOW_WRITES=true;
    action="unconclude" additionally requires FOSSA_ALLOW_DESTRUCTIVE=true, and
    so does any conclusion at organization or global scope.

    A conclusion overrides what FOSSA's scanners detected, so it decides which
    licensing issues exist and what the attribution report says. `scope` is
    required and never defaults: "project" needs project_locator, "revision"
    needs project_locator and revision_locator, "release_group" needs
    release_group_id, "release" needs both release ids, "organization" needs
    organization_id, and "global" is FOSSA-admin only and applies to every
    organization. Pass origin_id to have FOSSA rescan that revision or release
    for issues afterwards. Requires Edit permission on the dependency revision.
    """
    validated = LicenseConclusionInput(
        action=action,
        dependency_revision_locator=dependency_revision_locator,
        scope=scope,
        license_id=license_id,
        project_locator=project_locator,
        revision_locator=revision_locator,
        release_group_id=release_group_id,
        release_id=release_id,
        organization_id=organization_id,
        origin_id=origin_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    # Tier follows blast radius, not the verb. Removing a conclusion destroys
    # state and can reopen licensing issues across everything in scope, so it is
    # destructive wherever it is aimed. Adding one is an ordinary write unless
    # the scope is org-wide, where a single call re-licenses a dependency for
    # every project at once — the unbounded-target case the tier exists for.
    tier = (
        WriteTier.DESTRUCTIVE
        if validated.action == "unconclude" or validated.affects_whole_organization
        else WriteTier.WRITE
    )
    require_tier(settings, tier, "fossa_set_license_conclusion")

    body = validated.to_body()
    path = _LICENSE_CONCLUSION_PATHS[validated.action]

    result = await client.request_json("PUT", path, json_body=body)

    return {
        "ok": True,
        "endpoint": f"PUT {path}",
        "data": {"applied": body, "tier": tier.value, "conclusion": result},
    }


# --- builds ------------------------------------------------------------------

_BUILD_PATHS: dict[BuildView, str] = {
    "list": "/builds",
    "count": "/counts/builds",
}


async def get_builds(
    ctx: Context,
    view: BuildView = "list",
    locator: str | None = None,
    project_id: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int | None = None,
    page_size: int | None = None,
    sort: str | None = None,
) -> dict[str, Any]:
    """
    List FOSSA build records for a revision or project, or count them.

    Read-only. A build is one scan attempt, with its task status, warnings, and
    error — this is the "why has this revision not analyzed" view. Both
    parameters are documented as optional, but FOSSA answers 400 unless locator
    or project_id is given. `sort` is a comma-separated column list where a
    leading "-" means descending, over cliVersionId, createdAt, id, locator,
    ownerId, taskId, and updatedAt.
    """
    validated = BuildReadInput(
        view=view,
        locator=locator,
        project_id=project_id,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
        sort=sort,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = []
    if validated.locator is not None:
        params.append(("locator", validated.locator))
    if validated.project_id is not None:
        params.append(("projectId", validated.project_id))
    if validated.start_date is not None:
        params.append(("startDate", validated.start_date.isoformat()))
    if validated.end_date is not None:
        params.append(("endDate", validated.end_date.isoformat()))
    if validated.page_size is not None:
        params.append(("pageSize", str(validated.page_size)))
    if validated.page is not None:
        params.append(("page", str(validated.page)))
    if validated.sort is not None:
        params.append(("sort", validated.sort))

    path = _BUILD_PATHS[validated.view]
    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {path}", "data": result}


# --- vulnerabilities ---------------------------------------------------------


async def search_cves(
    ctx: Context,
    query: str,
) -> dict[str, Any]:
    """
    Search FOSSA's CVE catalog by identifier or text and return the matching
    CVEs with their descriptions.

    Read-only, and a catalog lookup rather than a finding: it answers "what is
    CVE-2021-44228" regardless of whether this organization is affected. Use
    fossa_list_issues with category="vulnerability" to find out which projects
    actually carry one. Requires the organization's security features to be on.
    """
    validated = CveSearchInput(query=query)

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    result = await client.request_json(
        "GET", "/vulns/cve-list", params=[("query", validated.query)]
    )

    return {"ok": True, "endpoint": "GET /vulns/cve-list", "data": result}


async def get_vulnerability_remediation(
    ctx: Context,
    vuln_id: str,
    revision_id: str,
) -> dict[str, Any]:
    """
    Ask which version of one dependency revision fixes one vulnerability, and
    how far away that version is.

    Read-only. Returns a partial fix and a complete fix, each with the semver
    distance — MAJOR, MINOR, or PATCH — so an upgrade can be judged before it is
    attempted. This is the single-vulnerability answer;
    fossa_get_revision_remediation_guidance returns the whole report for a
    project revision instead.
    """
    validated = VulnerabilityRemediationInput(vuln_id=vuln_id, revision_id=revision_id)

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    path = (
        f"/vulns/{_encode(validated.vuln_id)}"
        f"/revisions/{_encode(validated.revision_id)}/remediation-guidance"
    )
    result = await client.request_json("GET", path)

    return {
        "ok": True,
        "endpoint": "GET /vulns/{vulnId}/revisions/{revisionId}/remediation-guidance",
        "data": result,
    }


# --- organization capabilities -----------------------------------------------


async def get_cli_organization(ctx: Context) -> dict[str, Any]:
    """
    Read the organization's CLI capabilities and defaults: subscription level,
    which scan types are supported, and what the CLI should do by default.

    Read-only. This is the fastest way to find out whether a feature is even
    available before a tool call fails with a 403 — first-party scans, native
    container scans, path dependencies, snippet retention, and the Free vs
    Premium subscription level are all reported here.
    """
    client: FossaClient = ctx.request_context.lifespan_context["client"]

    result = await client.request_json("GET", "/cli/organization")

    return {"ok": True, "endpoint": "GET /cli/organization", "data": result}


async def get_github_app_installation_url(ctx: Context) -> dict[str, Any]:
    """
    Get the URL a FOSSA administrator opens to install the FOSSA GitHub App.

    Read-only, and it installs nothing: the returned URL has to be opened by a
    human with GitHub admin rights on the target organization. 404 means the
    GitHub App is not configured for this FOSSA instance.

    The URL is returned, not followed. Verified live, it is a constant public
    GitHub App installation URL with no `state`, `code`, or nonce, so it is safe
    to show and reuse; following it would only fetch a GitHub HTML page.
    """
    client: FossaClient = ctx.request_context.lifespan_context["client"]

    # The spec documents no 2xx for this endpoint at all — the whole payload is
    # the Location header of a 302.
    status_code, location = await client.request_redirect_location(
        "GET", "/services/github-app/installation-url"
    )

    return {
        "ok": True,
        "endpoint": "GET /services/github-app/installation-url",
        "data": {"installation_url": location, "status_code": status_code},
    }
