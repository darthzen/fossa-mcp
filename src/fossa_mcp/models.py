"""Pydantic models for FOSSA MCP server."""

from typing import List, Optional, Literal, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# Input models for tools
class ProjectListInput(BaseModel):
    """Input model for fossa_list_projects."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = None
    types: Optional[List[Literal["container", "archive", "provided", "autobuild", "sbom", "binary"]]] = None
    is_public: Optional[bool] = None
    labels: Optional[List[str]] = None
    team_ids: Optional[List[str]] = None
    latest_scan_days: Optional[int] = None
    last_revision_within_days: Optional[int] = None
    locators: Optional[List[str]] = None
    include_shared_projects: Optional[bool] = None
    only_include_shared_projects: Optional[bool] = None
    inventory: Optional[List[Literal["snippet", "vendored"]]] = None
    sort: Optional[Literal[
        "title_asc", "title_desc",
        "issues-total_asc", "issues-total_desc",
        "latest-scan_asc", "latest-scan_desc",
        "last-analyzed_asc", "last-analyzed_desc",
        "issues-licensing_asc", "issues-licensing_desc",
        "issues-security_asc", "issues-security_desc",
        "issues-quality_asc", "issues-quality_desc"
    ]] = None
    page: int = 1
    count: int = 20

    # Validation
    model_validator = None


class RevisionListInput(BaseModel):
    """Input model for fossa_list_project_revisions."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str
    offset: int = 0
    count: int = 20
    resolved_only: bool = True
    refs: Optional[List[str]] = None
    refs_type: Optional[Literal["branch", "tag"]] = None
    source: Optional[Literal[
        "github", "gitlab", "bitbucket", "azure",
        "cli", "archive", "container", "sbom", "binary"
    ]] = None
    minimal: bool = True
    locator_contains: Optional[str] = None

    # Validation
    model_validator = None


class DependencyListInput(BaseModel):
    """Input model for fossa_list_dependencies."""

    model_config = ConfigDict(extra="forbid")

    revision_locator: str
    dependency_locators: Optional[List[str]] = None
    title: Optional[str] = None
    statuses: Optional[List[Literal["analyzing", "analyzed", "failed", "unknown"]]] = None
    depths: Optional[List[Literal["direct", "transitive"]]] = None
    layer_depths: Optional[List[Literal["base", "other"]]] = None
    has_issues: Optional[List[Literal[
        "hasIssues", "hasLicensingIssues", "hasQualityIssues", "hasVulnIssues", "noIssues"
    ]]] = None
    licenses: Optional[List[str]] = None
    fetchers: Optional[List[str]] = None
    show_ignored: bool = False
    confidence: Optional[List[Literal["High", "Medium", "Low", "Unknown"]]] = None
    sources: Optional[List[Literal["managed", "vendored"]]] = None
    package_labels: Optional[List[str]] = None
    vendored_path: Optional[str] = None
    include_resolution_notes: bool = False
    include_license_text: bool = False
    include_copyright: bool = False
    include_matches: bool = False
    include_download_url: bool = False
    page: int = 1
    count: int = 20

    # Validation
    model_validator = None


class IssueListInput(BaseModel):
    """Input model for fossa_list_issues."""

    model_config = ConfigDict(extra="forbid")

    category: Literal["licensing", "vulnerability", "quality"]
    status: Literal["active", "ignored"] = "active"
    scope_type: Literal["global", "project"] = "global"
    project_locator: Optional[str] = None
    revision_locator: Optional[str] = None
    compare_to_revision: Optional[str] = None
    change_status: Optional[Literal["new", "remediated", "unchanged"]] = None
    issue_ids: Optional[List[int]] = None
    search: Optional[str] = None
    depths: Optional[List[Literal["direct", "deep"]]] = None
    issue_types: Optional[List[str]] = None
    package_managers: Optional[List[str]] = None
    cwes: Optional[List[str]] = None
    project_labels: Optional[List[str]] = None
    severity: Optional[List[Literal["critical", "high", "medium", "low", "unknown"]]] = None
    severity_source: Optional[List[Literal["standard", "custom"]]] = None
    found_before: Optional[datetime] = None
    found_after: Optional[datetime] = None
    issue_source: Optional[List[str]] = None
    sort: Optional[Literal[
        "package_asc", "package_desc",
        "created_at_asc", "created_at_desc",
        "severity_asc", "severity_desc",
        "epss_asc", "epss_desc"
    ]] = None
    include_direct_dependency_origin_paths: bool = False
    page: int = 1
    count: int = 20

    # Validation
    model_validator = None


class PostureInput(BaseModel):
    """Input model for fossa_project_posture."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str
    revision_locator: str
    top_issue_count: int = 10

    # Validation
    model_validator = None


class AttributionReportInput(BaseModel):
    """Input model for fossa_get_attribution_report."""

    model_config = ConfigDict(extra="forbid")

    revision_locator: str
    format: Literal["MD", "TXT", "SPDX_JSON", "CYCLONEDX_JSON"] = "MD"
    include_deep_dependencies: bool = True
    include_direct_dependencies: bool = True
    include_license_list: bool = True
    include_license_scan: bool = False
    include_project_license: bool = True
    include_copyright_list: bool = False
    include_file_matches: bool = False
    include_open_vulnerabilities: bool = False
    include_closed_vulnerabilities: bool = False
    include_dependency_summary: bool = True
    include_license_headers: bool = False
    include_package_labels: bool = False
    include_hash_and_version_data: bool = False

    # Validation
    model_validator = None


# Response models for tools
class ToolResponse(BaseModel):
    """Base response model for MCP tools."""

    ok: bool = True
    endpoint: str
    data: Any
    meta: Optional[dict] = None


class PostureResponse(BaseModel):
    """Response model for fossa_project_posture."""

    ok: bool = True
    project_locator: str
    revision_locator: str
    issue_counts: dict[str, int]
    top_vulnerability_issues: List[Any]
    top_licensing_issues: List[Any]
    top_quality_issues: List[Any]
    direct_dependencies_with_issues: List[Any]
    analysis_state: Literal["complete", "in_progress"]