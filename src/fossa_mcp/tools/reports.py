"""Report-related tools for the FOSSA MCP server."""

import json
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import AttributionReportInput, ReportFormat

_ENDPOINT = "GET /v2/revisions/{locator}/attribution/download"

_TEXT_FORMATS = ("MD", "TXT")
_JSON_FORMATS = ("SPDX_JSON", "CYCLONEDX_JSON")


async def get_attribution_report(
    ctx: Context,
    revision_locator: str,
    format: ReportFormat = "MD",
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
) -> dict[str, Any]:
    """Retrieve a text-friendly FOSSA attribution/SBOM report for a revision."""
    validated = AttributionReportInput(
        revision_locator=revision_locator,
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
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    params: list[tuple[str, str]] = [
        ("format", validated.format),
        ("includeDeepDependencies", str(validated.include_deep_dependencies).lower()),
        ("includeDirectDependencies", str(validated.include_direct_dependencies).lower()),
        ("includeLicenseList", str(validated.include_license_list).lower()),
        ("includeLicenseScan", str(validated.include_license_scan).lower()),
        ("includeProjectLicense", str(validated.include_project_license).lower()),
        ("includeCopyrightList", str(validated.include_copyright_list).lower()),
        ("includeFileMatches", str(validated.include_file_matches).lower()),
        ("includeOpenVulnerabilities", str(validated.include_open_vulnerabilities).lower()),
        ("includeClosedVulnerabilities", str(validated.include_closed_vulnerabilities).lower()),
        ("includeDependencySummary", str(validated.include_dependency_summary).lower()),
        ("includeLicenseHeaders", str(validated.include_license_headers).lower()),
        ("includePackageLabels", str(validated.include_package_labels).lower()),
        ("includeHashAndVersionData", str(validated.include_hash_and_version_data).lower()),
    ]

    encoded_locator = quote(validated.revision_locator, safe="")
    path = f"/v2/revisions/{encoded_locator}/attribution/download"

    content, content_type = await client.request_text("GET", path, params=params)

    # Cap raw text uniformly for every format before any further processing,
    # so JSON formats are truncated too, not just MD/TXT.
    original_char_count = len(content)
    truncated = original_char_count > settings.fossa_report_max_chars
    display_text = content[: settings.fossa_report_max_chars] if truncated else content

    if validated.format in _TEXT_FORMATS:
        content_value: Any = display_text
        json_parse_error = False
    else:
        try:
            content_value = json.loads(display_text)
            json_parse_error = False
        except json.JSONDecodeError:
            content_value = display_text
            json_parse_error = True

    # This tool's result shape is defined directly by the scope (§13.9) rather
    # than the standard `{ok, endpoint, data}` envelope used by the JSON-backed
    # tools: report content sits at the top level, not under `data`.
    result: dict[str, Any] = {
        "ok": True,
        "endpoint": _ENDPOINT,
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
