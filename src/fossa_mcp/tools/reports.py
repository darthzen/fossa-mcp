"""Report-related tools for FOSSA MCP server."""

import asyncio
import json
from typing import List, Optional, Any, Dict
from mcp.server import ToolContext

from ..client import FossaClient
from ..models import AttributionReportInput, ToolResponse


async def get_attribution_report(
    context: ToolContext,
    revision_locator: str,
    format: str = "MD",
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
) -> ToolResponse:
    """
    Retrieve a text-friendly FOSSA attribution/SBOM report for a revision.

    Args:
        context: MCP tool context
        revision_locator: The revision locator to get report for
        format: Report format ("MD", "TXT", "SPDX_JSON", or "CYCLONEDX_JSON")
        include_deep_dependencies: Include deep dependencies
        include_direct_dependencies: Include direct dependencies
        include_license_list: Include license list
        include_license_scan: Include license scan
        include_project_license: Include project license
        include_copyright_list: Include copyright list
        include_file_matches: Include file matches
        include_open_vulnerabilities: Include open vulnerabilities
        include_closed_vulnerabilities: Include closed vulnerabilities
        include_dependency_summary: Include dependency summary
        include_license_headers: Include license headers
        include_package_labels: Include package labels
        include_hash_and_version_data: Include hash and version data

    Returns:
        Tool response with attribution report
    """
    # Build query parameters
    params: List[tuple[str, str]] = []

    # Add format parameter
    params.append(("format", format))

    # Add boolean parameters
    params.append(("includeDeepDependencies", str(include_deep_dependencies).lower()))
    params.append(("includeDirectDependencies", str(include_direct_dependencies).lower()))
    params.append(("includeLicenseList", str(include_license_list).lower()))
    params.append(("includeLicenseScan", str(include_license_scan).lower()))
    params.append(("includeProjectLicense", str(include_project_license).lower()))
    params.append(("includeCopyrightList", str(include_copyright_list).lower()))
    params.append(("includeFileMatches", str(include_file_matches).lower()))
    params.append(("includeOpenVulnerabilities", str(include_open_vulnerabilities).lower()))
    params.append(("includeClosedVulnerabilities", str(include_closed_vulnerabilities).lower()))
    params.append(("includeDependencySummary", str(include_dependency_summary).lower()))
    params.append(("includeLicenseHeaders", str(include_license_headers).lower()))
    params.append(("includePackageLabels", str(include_package_labels).lower()))
    params.append(("includeHashAndVersionData", str(include_hash_and_version_data).lower()))

    # Encode the locator in the path (exactly once)
    encoded_locator = revision_locator  # This will be URL-encoded by the client

    # Make the API call
    client: FossaClient = context.state["client"]

    # For text formats, we get text response
    if format in ["MD", "TXT"]:
        content, content_type = await client.request_text("GET", f"/v2/revisions/{encoded_locator}/attribution/download", params=params)

        # Create the result structure
        result = {
            "ok": True,
            "format": format,
            "content_type": content_type,
            "truncated": False,
            "content": content,
        }

        # Apply truncation if needed
        if len(content) > context.settings.fossa_report_max_chars:
            result["truncated"] = True
            result["original_char_count"] = len(content)
            result["content"] = content[:context.settings.fossa_report_max_chars]

        return ToolResponse(
            endpoint="GET /v2/revisions/{locator}/attribution/download",
            data=result
        )

    # For JSON formats, we get JSON response
    elif format in ["SPDX_JSON", "CYCLONEDX_JSON"]:
        try:
            result = await client.request_json("GET", f"/v2/revisions/{encoded_locator}/attribution/download", params=params)

            # Try to parse as JSON and handle appropriately
            if isinstance(result, str):
                try:
                    parsed_result = json.loads(result)
                    return ToolResponse(
                        endpoint="GET /v2/revisions/{locator}/attribution/download",
                        data={
                            "ok": True,
                            "format": format,
                            "content_type": "application/json",
                            "truncated": False,
                            "content": parsed_result,
                        }
                    )
                except json.JSONDecodeError:
                    # If we can't parse it, return the text with error flag
                    return ToolResponse(
                        endpoint="GET /v2/revisions/{locator}/attribution/download",
                        data={
                            "ok": True,
                            "format": format,
                            "content_type": "application/json",
                            "truncated": False,
                            "content": result,
                            "json_parse_error": True
                        }
                    )
            else:
                return ToolResponse(
                    endpoint="GET /v2/revisions/{locator}/attribution/download",
                    data={
                        "ok": True,
                        "format": format,
                        "content_type": "application/json",
                        "truncated": False,
                        "content": result,
                    }
                )
        except Exception as e:
            # If we get an error, try to return it as text
            content, content_type = await client.request_text("GET", f"/v2/revisions/{encoded_locator}/attribution/download", params=params)

            # Try to parse it if possible
            try:
                parsed_result = json.loads(content)
                return ToolResponse(
                    endpoint="GET /v2/revisions/{locator}/attribution/download",
                    data={
                        "ok": True,
                        "format": format,
                        "content_type": content_type,
                        "truncated": False,
                        "content": parsed_result,
                    }
                )
            except json.JSONDecodeError:
                # Return as text with error flag
                return ToolResponse(
                    endpoint="GET /v2/revisions/{locator}/attribution/download",
                    data={
                        "ok": True,
                        "format": format,
                        "content_type": content_type,
                        "truncated": False,
                        "content": content,
                        "json_parse_error": True
                    }
                )

    else:
        raise ValueError(f"Unsupported format: {format}")