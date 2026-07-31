"""Pydantic models for the FOSSA MCP server.

These models are constructed inside each tool function from the tool's flat,
individually-typed parameters (the shape FastMCP needs to build an accurate
JSON input schema). Constructing the model runs field- and model-level
validation before any FOSSA HTTP request is made.

This module holds the shared `Literal` aliases and the models for the original
read tools. Models added by the API-parity work live in a sibling module per
domain — `models/projects.py`, `models/issues.py`, and so on — mirroring
`tools/`, so that one domain's models can be read without paging through
twenty others'. Import them from their own module (`from ..models.projects
import ProjectUpdateInput`); this package's namespace is deliberately not a
re-export surface for them.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Shared enum aliases, reused by both the models below and tool signatures.
ProjectType = Literal["container", "archive", "provided", "autobuild", "sbom", "binary"]
InventoryType = Literal["snippet", "vendored"]
ProjectSort = Literal[
    "title_asc",
    "title_desc",
    "issues-total_asc",
    "issues-total_desc",
    "latest-scan_asc",
    "latest-scan_desc",
    "last-analyzed_asc",
    "last-analyzed_desc",
    "issues-licensing_asc",
    "issues-licensing_desc",
    "issues-security_asc",
    "issues-security_desc",
    "issues-quality_asc",
    "issues-quality_desc",
]
RefType = Literal["branch", "tag"]
RevisionSource = Literal[
    "github", "gitlab", "bitbucket", "azure", "cli", "archive", "container", "sbom", "binary"
]
DependencyStatus = Literal["analyzing", "analyzed", "failed", "unknown"]
DependencyDepth = Literal["direct", "transitive"]
LayerDepth = Literal["base", "other"]
HasIssues = Literal[
    "hasIssues", "hasLicensingIssues", "hasQualityIssues", "hasVulnIssues", "noIssues"
]
Confidence = Literal["High", "Medium", "Low", "Unknown"]
DependencySource = Literal["managed", "vendored"]
IssueCategory = Literal["licensing", "vulnerability", "quality"]
IssueStatus = Literal["active", "ignored"]
ScopeType = Literal["global", "project"]
ChangeStatus = Literal["new", "remediated", "unchanged"]
IssueDepth = Literal["direct", "deep"]
Severity = Literal["critical", "high", "medium", "low", "unknown"]
SeveritySource = Literal["standard", "custom"]
IssueSort = Literal[
    "package_asc",
    "package_desc",
    "created_at_asc",
    "created_at_desc",
    "severity_asc",
    "severity_desc",
    "epss_asc",
    "epss_desc",
]
ReportFormat = Literal["MD", "TXT", "SPDX_JSON", "CYCLONEDX_JSON"]


# Input models for tools
class ProjectListInput(BaseModel):
    """Input model for fossa_list_projects."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    types: list[ProjectType] | None = None
    is_public: bool | None = None
    labels: list[str] | None = None
    team_ids: list[str] | None = None
    latest_scan_days: int | None = Field(default=None, ge=0)
    last_revision_within_days: int | None = Field(default=None, ge=0)
    locators: list[str] | None = None
    include_shared_projects: bool | None = None
    only_include_shared_projects: bool | None = None
    inventory: list[InventoryType] | None = None
    sort: ProjectSort | None = None
    page: int = Field(default=1, ge=1)
    count: int = Field(default=20, ge=1)


class RevisionListInput(BaseModel):
    """Input model for fossa_list_project_revisions."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    offset: int = Field(default=0, ge=0)
    count: int = Field(default=20, ge=1)
    resolved_only: bool = True
    refs: list[str] | None = None
    refs_type: RefType | None = None
    source: RevisionSource | None = None
    minimal: bool = True
    locator_contains: str | None = None


class DependencyListInput(BaseModel):
    """Input model for fossa_list_dependencies."""

    model_config = ConfigDict(extra="forbid")

    revision_locator: str = Field(min_length=1)
    dependency_locators: list[str] | None = None
    title: str | None = None
    statuses: list[DependencyStatus] | None = None
    depths: list[DependencyDepth] | None = None
    layer_depths: list[LayerDepth] | None = None
    has_issues: list[HasIssues] | None = None
    licenses: list[str] | None = None
    fetchers: list[str] | None = None
    show_ignored: bool = False
    confidence: list[Confidence] | None = None
    sources: list[DependencySource] | None = None
    package_labels: list[str] | None = None
    vendored_path: str | None = None
    include_resolution_notes: bool = False
    include_license_text: bool = False
    include_copyright: bool = False
    include_matches: bool = False
    include_download_url: bool = False
    page: int = Field(default=1, ge=1)
    count: int = Field(default=20, ge=1)


class IssueListInput(BaseModel):
    """Input model for fossa_list_issues."""

    model_config = ConfigDict(extra="forbid")

    category: IssueCategory
    status: IssueStatus = "active"
    scope_type: ScopeType = "global"
    project_locator: str | None = None
    revision_locator: str | None = None
    compare_to_revision: str | None = None
    change_status: ChangeStatus | None = None
    issue_ids: list[int] | None = None
    search: str | None = None
    depths: list[IssueDepth] | None = None
    issue_types: list[str] | None = None
    package_managers: list[str] | None = None
    cwes: list[str] | None = None
    project_labels: list[str] | None = None
    severity: list[Severity] | None = None
    severity_source: list[SeveritySource] | None = None
    found_before: datetime | None = None
    found_after: datetime | None = None
    issue_source: list[str] | None = None
    sort: IssueSort | None = None
    include_direct_dependency_origin_paths: bool = False
    page: int = Field(default=1, ge=1)
    count: int = Field(default=20, ge=1)

    @model_validator(mode="after")
    def _validate_scope_and_filters(self) -> "IssueListInput":
        if self.scope_type == "global":
            if self.project_locator is not None:
                raise ValueError("project_locator must be None for global scope")
            if self.revision_locator is not None:
                raise ValueError("revision_locator must be None for global scope")
            if self.compare_to_revision is not None:
                raise ValueError("compare_to_revision must be None for global scope")
            if self.change_status is not None:
                raise ValueError("change_status must be None for global scope")
        else:
            if self.project_locator is None:
                raise ValueError("project_locator is required for project scope")
            if self.revision_locator is None:
                raise ValueError("revision_locator is required for project scope")
            if (self.compare_to_revision is not None) != (self.change_status is not None):
                raise ValueError(
                    "compare_to_revision and change_status must be set together or both unset"
                )

        if self.category != "vulnerability":
            if self.severity is not None:
                raise ValueError("severity filter is only allowed for vulnerability category")
            if self.severity_source is not None:
                raise ValueError(
                    "severity_source filter is only allowed for vulnerability category"
                )
            if self.cwes is not None:
                raise ValueError("cwes filter is only allowed for vulnerability category")
        elif self.issue_types is not None:
            raise ValueError("issue_types is not allowed for vulnerability category")

        return self


class PostureInput(BaseModel):
    """Input model for fossa_project_posture."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    top_issue_count: int = Field(default=10, ge=1, le=25)


class SecurityPolicyReadInput(BaseModel):
    """Input model for fossa_get_security_policy."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)


class PolicyEvaluateInput(BaseModel):
    """Input model for fossa_evaluate_security_policy."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    depths: list[DependencyDepth] | None = None
    count: int = Field(default=100, ge=1)


class PolicyEnableInput(BaseModel):
    """Input model for fossa_enable_security_policy."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    security_policy_id: int = Field(ge=1)
    enable_scanning: bool = True
    enable_status_check: bool = True


class PackageBlockInput(BaseModel):
    """Input model for fossa_block_package.

    `package_locator` is deliberately versionless. FOSSA carries the version
    scope in the body (`versions`), not in the locator, so accepting
    `pip+aiofile$1.2.3` here would send the version to the server as part of the
    package identity and create a rule that matches nothing.
    """

    model_config = ConfigDict(extra="forbid")

    package_locator: str = Field(min_length=1)
    policy_ids: list[int] = Field(min_length=1)
    versions: list[str] | None = None

    @model_validator(mode="after")
    def _validate_locator_and_versions(self) -> "PackageBlockInput":
        if "$" in self.package_locator:
            raise ValueError(
                "package_locator must be versionless (e.g. 'pip+aiofile', not "
                "'pip+aiofile$1.2.3'); scope the block with versions=['1.2.3'] instead"
            )
        if any(policy_id < 1 for policy_id in self.policy_ids):
            raise ValueError("policy_ids must all be >= 1")

        if self.versions is not None:
            # FOSSA accepts `[]` and treats it as every version. That makes an
            # accidentally-empty list silently block the whole package, so an
            # empty list is rejected here and omitting the argument is the only
            # way to ask for every version.
            if not self.versions:
                raise ValueError(
                    "versions must name at least one version; omit it to block every version"
                )
            if any(not version.strip() for version in self.versions):
                raise ValueError("versions must not contain blank entries")

        return self


class PackageUnblockInput(BaseModel):
    """Input model for fossa_unblock_package."""

    model_config = ConfigDict(extra="forbid")

    package_locator: str = Field(min_length=1)
    policy_id: int = Field(ge=1)

    @model_validator(mode="after")
    def _validate_locator(self) -> "PackageUnblockInput":
        if "$" in self.package_locator:
            raise ValueError(
                "package_locator must be versionless (e.g. 'pip+aiofile', not "
                "'pip+aiofile$1.2.3'); a block rule is removed for the whole package"
            )
        return self


class AttributionReportInput(BaseModel):
    """Input model for fossa_get_attribution_report."""

    model_config = ConfigDict(extra="forbid")

    revision_locator: str = Field(min_length=1)
    format: ReportFormat = "MD"
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


# Response models for tools.
#
# Direct JSON-backed tools return plain dicts built as the standard envelope
# (see server.py / tools/*.py) rather than a shared response model, so that
# optional keys (`meta`, `state`, `message`) are only present when set instead
# of always appearing as `null`. `fossa_project_posture` has a fixed, richer
# shape and is modeled explicitly below.
class PostureResponse(BaseModel):
    """Response model for fossa_project_posture."""

    ok: bool = True
    project_locator: str
    revision_locator: str
    issue_counts: dict[str, int]
    top_vulnerability_issues: list[Any]
    top_licensing_issues: list[Any]
    top_quality_issues: list[Any]
    direct_dependencies_with_issues: list[Any]
    analysis_state: Literal["complete", "in_progress"]
