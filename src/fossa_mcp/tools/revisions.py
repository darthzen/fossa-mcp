"""Revision-related tools for the FOSSA MCP server.

A revision is addressed by the joined `project$revision` locator, which every
tool here builds with `split_revision_locator` and percent-encodes whole
(`quote(..., safe="")`) because locators contain `+`, `/`, and `$`. Callers may
pass either the bare revision id or the full locator as `revision_locator`.

Three of the endpoints in this domain do not answer with JSON: the remediation
guidance and rendered attribution reports are documents, and the original SBOM
is a redirect to one. Those go through `client.request_text` rather than being
forced through a JSON parse.
"""

import json
import re
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..errors import FossaApiError
from ..models import RefType, RevisionListInput, RevisionSource
from ..models.revisions import (
    ATTRIBUTION_JSON_QUERY_NAMES,
    REPORT_OPTION_QUERY_NAMES,
    AttributionApiVersion,
    AttributionFormat,
    AttributionRenderFormat,
    AttributionRenderVariant,
    DependencyTransport,
    PublicAttributionReportInput,
    RemediationFormat,
    RemediationGuidanceInput,
    RevisionAttributionEmailInput,
    RevisionAttributionJsonInput,
    RevisionAttributionRenderInput,
    RevisionDependenciesV1Input,
    RevisionNoticeFilesInput,
    RevisionSbomInput,
    RevisionScansInput,
    RevisionUpdateInput,
    SbomPart,
)
from ..query import add_repeated, bool_to_str, split_revision_locator
from ..writes import WriteTier, require_tier

# Formats whose body is JSON, and so is worth parsing before returning it.
_JSON_REPORT_FORMATS = ("SPDX_JSON", "CYCLONEDX_JSON")

# Redirect statuses FOSSA may answer a document request with. `GET
# /revisions/{locator}/original-sbom` documents 302 as its success case.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")

# The number of characters of dependency locators above which the query string
# is switched for a request body. FOSSA documents the POST twin of the v1
# dependencies endpoint for exactly this case.
_LOCATOR_QUERY_BUDGET = 1500


def _revision_locators(project_locator: str, revision_locator: str) -> tuple[str, str]:
    """Return `(full_locator, url_encoded_locator)` for a revision path."""
    full_locator, _ = split_revision_locator(project_locator, revision_locator)
    return full_locator, quote(full_locator, safe="")


def _exclude_fields_params(labels: list[str] | None) -> list[tuple[str, str]]:
    """Serialize `excludeFields[packageLabels]`.

    FOSSA parses the query string with `qs`, so the array goes over the wire in
    bracket-and-index form rather than OpenAPI's `deepObject` serialization.
    The spec says so explicitly for the v1 JSON report; the v2 paths are the
    same server.
    """
    return [
        (f"excludeFields[packageLabels][{index}]", label)
        for index, label in enumerate(labels or [])
    ]


def _truncate(text: str, limit: int) -> tuple[str, bool, int]:
    """Cap report text at `limit`, reporting whether anything was dropped."""
    original_char_count = len(text)
    truncated = original_char_count > limit
    return (text[:limit] if truncated else text), truncated, original_char_count


def _document_payload(
    content: str, content_type: str | None, report_format: str, limit: int
) -> dict[str, Any]:
    """Build the `data` block for a report that arrives as a document."""
    display_text, truncated, original_char_count = _truncate(content, limit)

    parsed: Any = display_text
    json_parse_error = False
    if report_format in _JSON_REPORT_FORMATS or report_format == "JSON":
        try:
            parsed = json.loads(display_text)
        except json.JSONDecodeError:
            json_parse_error = True

    payload: dict[str, Any] = {
        "format": report_format,
        "content_type": content_type,
        "truncated": truncated,
        "content": parsed,
    }
    if truncated:
        payload["original_char_count"] = original_char_count
        # A truncated JSON document cannot parse; say that plainly rather than
        # reporting a parse failure that is really a size limit.
        payload["json_parse_error"] = json_parse_error
    elif json_parse_error:
        payload["json_parse_error"] = True
    return payload


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


async def list_revision_scans(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    page: int = 1,
    page_size: int = 10,
) -> dict[str, Any]:
    """List the policy scans FOSSA has run against a revision, newest first.

    Each entry names the licensing, security, and quality policy versions that
    were in force for that scan, which is how to tell whether a finding predates
    a policy change.
    """
    validated = RevisionScansInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        page=page,
        page_size=page_size,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)
    params = [("page", str(validated.page)), ("pageSize", str(validated.page_size))]

    result = await client.request_json("GET", f"/revisions/{encoded_locator}/scans", params=params)

    return {"ok": True, "endpoint": "GET /revisions/{locator}/scans", "data": result}


async def get_revision_notice_files(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    include_contents: bool = True,
) -> dict[str, Any]:
    """Return the NOTICE files FOSSA found in a revision's distributed source.

    Set `include_contents=False` for just the paths and copyright lines. Notice
    text is capped in total at FOSSA_REPORT_MAX_CHARS across all files, and the
    files that were cut carry `contents_truncated`.
    """
    validated = RevisionNoticeFilesInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        include_contents=include_contents,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)
    result = await client.request_json("GET", f"/revisions/{encoded_locator}/notice-files")

    items = [item for item in result if isinstance(item, dict)] if isinstance(result, list) else []

    truncated = False
    notice_files: list[dict[str, Any]] = []
    remaining = settings.fossa_report_max_chars
    for item in items:
        contents = item.get("contents")
        if not validated.include_contents:
            notice_files.append({key: value for key, value in item.items() if key != "contents"})
            continue
        if isinstance(contents, str) and len(contents) > remaining:
            notice_files.append(
                {**item, "contents": contents[:remaining], "contents_truncated": True}
            )
            remaining = 0
            truncated = True
            continue
        if isinstance(contents, str):
            remaining -= len(contents)
        notice_files.append(item)

    return {
        "ok": True,
        "endpoint": "GET /revisions/{locator}/notice-files",
        "data": {
            "notice_files": notice_files,
            "count": len(notice_files),
            "contents_included": validated.include_contents,
            "truncated": truncated,
        },
    }


async def get_revision_sbom(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    part: SbomPart = "analysis",
) -> dict[str, Any]:
    """Return FOSSA's analysis of an uploaded SBOM, or a link to the original file.

    `part="analysis"` reports what FOSSA made of the document: whether it parsed
    as an SBOM, which required fields were present, and how the dependency scan
    went. `part="original"` asks for the file as uploaded; FOSSA answers that
    with a redirect, so what comes back is the download URL, not the document.

    Both only apply to SBOM projects. Any other project type answers 400.
    """
    validated = RevisionSbomInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        part=part,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    if validated.part == "analysis":
        result = await client.request_json("GET", f"/revisions/{encoded_locator}/sbom-analysis")
        return {
            "ok": True,
            "endpoint": "GET /revisions/{locator}/sbom-analysis",
            "data": result,
        }

    # The documented success for this path is a 302 to a storage URL. The client
    # does not follow redirects and surfaces non-2xx as an error, so the
    # redirect arrives here as a FossaApiError carrying the response body; the
    # `Location` header is not available at this layer.
    try:
        content, content_type = await client.request_text(
            "GET", f"/revisions/{encoded_locator}/original-sbom"
        )
    except FossaApiError as exc:
        if exc.status_code not in _REDIRECT_STATUSES:
            raise
        match = _URL_IN_TEXT.search(exc.message)
        return {
            "ok": True,
            "endpoint": "GET /revisions/{locator}/original-sbom",
            "data": {
                "status_code": exc.status_code,
                "download_url": match.group(0) if match else None,
                "body": exc.message,
            },
        }

    display_text, truncated, original_char_count = _truncate(
        content, settings.fossa_report_max_chars
    )
    data: dict[str, Any] = {
        "status_code": 200,
        "content_type": content_type,
        "truncated": truncated,
        "content": display_text,
    }
    if truncated:
        data["original_char_count"] = original_char_count

    return {"ok": True, "endpoint": "GET /revisions/{locator}/original-sbom", "data": data}


async def get_revision_remediation_guidance(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    format: RemediationFormat = "JSON",
    exclude_quick_wins: bool = False,
    exclude_high_priority: bool = False,
    exclude_low_priority: bool = False,
    exclude_outdated_dependencies: bool = False,
    include_transitive_vulnerabilities: bool = False,
    deduplicate_outdated_dependencies: bool = False,
    include_malware: bool = False,
) -> dict[str, Any]:
    """Return FOSSA's remediation guidance report for a revision.

    The report is the ranked fix plan: quick wins, high and low priority work,
    and outdated dependencies.

    Requires a Premium subscription with Security enabled; other organizations
    get a 403. The endpoint also offers PDF and zip-bundle output, which this
    tool does not request because neither survives being returned as text.
    """
    validated = RemediationGuidanceInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        format=format,
        exclude_quick_wins=exclude_quick_wins,
        exclude_high_priority=exclude_high_priority,
        exclude_low_priority=exclude_low_priority,
        exclude_outdated_dependencies=exclude_outdated_dependencies,
        include_transitive_vulnerabilities=include_transitive_vulnerabilities,
        deduplicate_outdated_dependencies=deduplicate_outdated_dependencies,
        include_malware=include_malware,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    params: list[tuple[str, str]] = [
        ("format", validated.format),
        ("excludeQuickWins", bool_to_str(validated.exclude_quick_wins)),
        ("excludeHighPriority", bool_to_str(validated.exclude_high_priority)),
        ("excludeLowPriority", bool_to_str(validated.exclude_low_priority)),
        ("excludeOutdatedDependencies", bool_to_str(validated.exclude_outdated_dependencies)),
        ("includeTransitiveVulns", bool_to_str(validated.include_transitive_vulnerabilities)),
        ("deduplicateOutdatedDeps", bool_to_str(validated.deduplicate_outdated_dependencies)),
        ("includeMalware", bool_to_str(validated.include_malware)),
    ]

    content, content_type = await client.request_text(
        "GET", f"/revisions/{encoded_locator}/report/remediation-guidance", params=params
    )

    return {
        "ok": True,
        "endpoint": "GET /revisions/{locator}/report/remediation-guidance",
        "data": _document_payload(
            content, content_type, validated.format, settings.fossa_report_max_chars
        ),
    }


async def get_revision_attribution_json(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    api_version: AttributionApiVersion = "v2",
    preview: bool = False,
    include_deep_dependencies: bool = True,
    include_hash_and_version_data: bool = False,
    include_copyright_list: bool = False,
    include_file_matches: bool = False,
    include_open_vulnerabilities: bool = False,
    include_closed_vulnerabilities: bool = False,
    include_notice_files: bool = False,
    include_package_labels: bool = False,
    exclude_package_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Return a revision's attribution report as structured JSON.

    Prefer this over the rendered formats when the answer will be reasoned about
    rather than handed to a person. `api_version="v1"` calls the legacy path,
    which takes the same options and differs only in response shape.

    Requires a Premium subscription; other organizations get a 403. The response
    shape is not declared in the OpenAPI spec, so it is passed through as FOSSA
    returns it.
    """
    validated = RevisionAttributionJsonInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        api_version=api_version,
        preview=preview,
        include_deep_dependencies=include_deep_dependencies,
        include_hash_and_version_data=include_hash_and_version_data,
        include_copyright_list=include_copyright_list,
        include_file_matches=include_file_matches,
        include_open_vulnerabilities=include_open_vulnerabilities,
        include_closed_vulnerabilities=include_closed_vulnerabilities,
        include_notice_files=include_notice_files,
        include_package_labels=include_package_labels,
        exclude_package_labels=exclude_package_labels,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    params: list[tuple[str, str]] = [
        (query_name, bool_to_str(getattr(validated, field)))
        for field, query_name in ATTRIBUTION_JSON_QUERY_NAMES
    ]
    params.extend(_exclude_fields_params(validated.exclude_package_labels))

    prefix = "" if validated.api_version == "v1" else "/v2"
    result = await client.request_json(
        "GET", f"{prefix}/revisions/{encoded_locator}/attribution/json", params=params
    )

    endpoint = (
        "GET /revisions/{locator}/attribution/json"
        if validated.api_version == "v1"
        else "GET /v2/revisions/{locator}/attribution/json"
    )
    return {"ok": True, "endpoint": endpoint, "data": result}


async def render_revision_attribution(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    variant: AttributionRenderVariant = "stream",
    format: AttributionRenderFormat = "MD",
    include_deep_dependencies: bool = True,
    include_direct_dependencies: bool = True,
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
    include_hash_and_version_data: bool = False,
    exclude_package_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a revision's attribution report and return the rendered document.

    `variant="stream"` is the general report endpoint, `"preview"` renders it
    inline, and `"full"` turns on every report option server-side and therefore
    accepts no options here. For the plain file download use
    fossa_get_attribution_report.

    PDF is not offered: the document is returned as text and a PDF does not
    survive that. Output is capped at FOSSA_REPORT_MAX_CHARS.
    """
    validated = RevisionAttributionRenderInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        variant=variant,
        format=format,
        include_deep_dependencies=include_deep_dependencies,
        include_direct_dependencies=include_direct_dependencies,
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
        include_hash_and_version_data=include_hash_and_version_data,
        exclude_package_labels=exclude_package_labels,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    if validated.variant == "full":
        path = f"/v2/revisions/{encoded_locator}/attribution/full/{validated.format}"
        params: list[tuple[str, str]] = []
        endpoint = "GET /v2/revisions/{locator}/attribution/full/{format}"
    else:
        suffix = "/preview" if validated.variant == "preview" else ""
        path = f"/v2/revisions/{encoded_locator}/attribution{suffix}"
        params = [("format", validated.format)]
        params.extend(
            (query_name, bool_to_str(getattr(validated, field)))
            for field, query_name in REPORT_OPTION_QUERY_NAMES
        )
        params.append(
            ("includeHashAndVersionData", bool_to_str(validated.include_hash_and_version_data))
        )
        params.extend(_exclude_fields_params(validated.exclude_package_labels))
        endpoint = f"GET /v2/revisions/{{locator}}/attribution{suffix}"

    content, content_type = await client.request_text("GET", path, params=params)

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": _document_payload(
            content, content_type, validated.format, settings.fossa_report_max_chars
        ),
    }


async def list_revision_dependencies_v1(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    limit: int = 100,
    offset: int = 0,
    dependency_locators: list[str] | None = None,
    include_ignored: bool = False,
    include_hash_data: bool = False,
    include_license_text: bool = False,
    transport: DependencyTransport = "auto",
) -> dict[str, Any]:
    """List a revision's dependencies in FOSSA's legacy v1 response shape.

    The v1 shape carries the dependency lock, full license objects, and issue
    targets, none of which the v2 response includes.

    fossa_list_dependencies is the better default; this exists for the fields
    the v2 response drops and for filtering by a locator list too long for a
    query string. With `transport="auto"` a long locator list is sent as a
    request body instead, which is FOSSA's documented workaround for the URI
    size limit. Neither transport changes FOSSA state.
    """
    validated = RevisionDependenciesV1Input(
        project_locator=project_locator,
        revision_locator=revision_locator,
        limit=limit,
        offset=offset,
        dependency_locators=dependency_locators,
        include_ignored=include_ignored,
        include_hash_data=include_hash_data,
        include_license_text=include_license_text,
        transport=transport,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    locators = validated.dependency_locators or []
    if validated.transport == "auto":
        use_post = sum(len(locator) for locator in locators) > _LOCATOR_QUERY_BUDGET
    else:
        use_post = validated.transport == "post"

    if use_post:
        body: dict[str, Any] = {
            "limit": validated.limit,
            "offset": validated.offset,
            "include_ignored": validated.include_ignored,
            "includeHashData": validated.include_hash_data,
            "include_license_text": validated.include_license_text,
        }
        if locators:
            body["includeLocators"] = locators
        result = await client.request_json(
            "POST", f"/revisions/{encoded_locator}/list-dependencies", json_body=body
        )
        endpoint = "POST /revisions/{locator}/list-dependencies"
    else:
        params: list[tuple[str, str]] = [
            ("limit", str(validated.limit)),
            ("offset", str(validated.offset)),
            ("include_ignored", bool_to_str(validated.include_ignored)),
            ("includeHashData", bool_to_str(validated.include_hash_data)),
            ("include_license_text", bool_to_str(validated.include_license_text)),
        ]
        # `includeLocators` is a plain repeated parameter on this endpoint, not
        # the bracketed form the v2 endpoints use.
        params.extend(("includeLocators", locator) for locator in locators)
        result = await client.request_json(
            "GET", f"/revisions/{encoded_locator}/dependencies", params=params
        )
        endpoint = "GET /revisions/{locator}/dependencies"

    return {"ok": True, "endpoint": endpoint, "data": result}


async def update_revision(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    link: str | None = None,
    url: str | None = None,
    author: str | None = None,
) -> dict[str, Any]:
    """Update a revision's metadata: its link, url, or author.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Only the fields you pass are sent; the rest are left as they are. This edits
    the recorded provenance of an analyzed revision, not its analysis results.
    """
    validated = RevisionUpdateInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        link=link,
        url=url,
        author=author,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_update_revision")

    full_locator, encoded_locator = _revision_locators(
        validated.project_locator, validated.revision_locator
    )

    payload: dict[str, Any] = {}
    if validated.link is not None:
        payload["link"] = validated.link
    if validated.url is not None:
        payload["url"] = validated.url
    if validated.author is not None:
        payload["author"] = validated.author

    result = await client.request_json("PATCH", f"/revisions/{encoded_locator}", json_body=payload)

    return {
        "ok": True,
        "endpoint": "PATCH /revisions/{locator}",
        "data": {"revision_locator": full_locator, "applied": payload, "revision": result},
    }


async def email_revision_attribution(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    api_version: AttributionApiVersion = "v2",
    format: AttributionFormat = "PDF",
    preview: bool = False,
    include_deep_dependencies: bool = True,
    include_direct_dependencies: bool = True,
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
    exclude_package_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Email a revision's attribution report to the account behind the API token.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    The side effect is an outbound email rather than a change to FOSSA state,
    which is why it is gated despite being a GET. The response is the queued
    task, not the report. `api_version="v1"` calls the legacy path.
    """
    validated = RevisionAttributionEmailInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        api_version=api_version,
        format=format,
        preview=preview,
        include_deep_dependencies=include_deep_dependencies,
        include_direct_dependencies=include_direct_dependencies,
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
        exclude_package_labels=exclude_package_labels,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_email_revision_attribution")

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    params: list[tuple[str, str]] = [
        ("preview", bool_to_str(validated.preview)),
        ("format", validated.format),
    ]
    params.extend(
        (query_name, bool_to_str(getattr(validated, field)))
        for field, query_name in REPORT_OPTION_QUERY_NAMES
    )
    params.extend(_exclude_fields_params(validated.exclude_package_labels))

    prefix = "" if validated.api_version == "v1" else "/v2"
    result = await client.request_json(
        "GET", f"{prefix}/revisions/{encoded_locator}/attribution/email", params=params
    )

    endpoint = (
        "GET /revisions/{locator}/attribution/email"
        if validated.api_version == "v1"
        else "GET /v2/revisions/{locator}/attribution/email"
    )
    return {"ok": True, "endpoint": endpoint, "data": result}


async def create_public_attribution_report(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    format: AttributionFormat = "HTML",
    recipient_email: str | None = None,
    include_deep_dependencies: bool = True,
    include_direct_dependencies: bool = True,
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
    exclude_package_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Create a publicly reachable link to a revision's attribution report.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    The generated report is readable by anyone holding the URL, with no FOSSA
    login, so this publishes whatever the selected options include — dependency
    inventory, licenses, and optionally open vulnerabilities. Requires a Premium
    subscription. FOSSA answers 202: the record comes back immediately and the
    document is generated by the returned background task.
    """
    validated = PublicAttributionReportInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        format=format,
        recipient_email=recipient_email,
        include_deep_dependencies=include_deep_dependencies,
        include_direct_dependencies=include_direct_dependencies,
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
        exclude_package_labels=exclude_package_labels,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_public_attribution_report")

    _, encoded_locator = _revision_locators(validated.project_locator, validated.revision_locator)

    params: list[tuple[str, str]] = [("format", validated.format)]
    if validated.recipient_email is not None:
        params.append(("emails", validated.recipient_email))
    params.extend(
        (query_name, bool_to_str(getattr(validated, field)))
        for field, query_name in REPORT_OPTION_QUERY_NAMES
    )
    params.extend(_exclude_fields_params(validated.exclude_package_labels))

    status_code, result = await client.request_json_with_status(
        "POST", f"/v2/revisions/{encoded_locator}/attribution/public", params=params
    )

    return {
        "ok": True,
        "endpoint": "POST /v2/revisions/{locator}/attribution/public",
        "data": {"status_code": status_code, "queued": status_code == 202, "report": result},
    }
