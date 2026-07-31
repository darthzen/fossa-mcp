"""Input models for the inventory long-tail tools.

This module covers the domains that are mostly read surface and share no
locator model with each other: binary decomposition, package observability,
components, audit logs, SBOM sharing, license conclusions, builds,
vulnerabilities, and the two organization capability endpoints.

Three things here are worth stating up front, because getting them wrong is
silent rather than loud:

* **The binary and package tools are grouped, so their discriminators are
  `Literal`s.** `scope`, `view`, and `section` select which FOSSA endpoint is
  called. An unknown value must be a schema error at the client, not a 404 from
  FOSSA, which is why each one is a closed `Literal` and why every model
  validates that the arguments the chosen branch does not use are absent rather
  than quietly ignoring them.
* **`GET /packages` serializes its array filters with bracket-and-index
  notation** (`fetchers[0]=npm&fetchers[1]=apk`), not with the `[]` suffix the
  issue endpoints use. The spec documents this in its own parameter examples;
  `tools/inventory.py` has the serializer.
* **License conclusion scope is a six-branch `oneOf` and it never defaults.**
  Every branch names its own required ids, and `organization` and `global` are
  org-wide. `LicenseConclusionInput` reproduces the discriminated union exactly:
  the scope is required, each branch's ids are required, and any id belonging to
  a different branch is rejected rather than dropped. Nothing here can widen a
  project-scoped conclusion into an org-wide one by omission.
"""

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import Severity

# --- binary decomposition ----------------------------------------------------

# Binary endpoints come in revision-addressed and release-addressed pairs. The
# two take different path parameters, so the scope decides both the path and
# which ids are required.
BinaryScope = Literal["revision", "release"]
BinaryComponentView = Literal["count", "paths"]
BinaryRevisionView = Literal["component_matches", "dependency_components"]

# --- package observability ---------------------------------------------------

PackageObservabilitySection = Literal["summary", "package_managers", "locators"]

PackageFetcher = Literal[
    "apk",
    "bower",
    "cargo",
    "cart",
    "comp",
    "conda",
    "cpan",
    "cran",
    "deb",
    "gem",
    "git",
    "go",
    "hackage",
    "hex",
    "mvn",
    "npm",
    "nuget",
    "pip",
    "pod",
    "pub",
    "rpm",
    "rpm-generic",
    "swift",
]
PackageDepth = Literal["direct", "transitive"]
PackageVisibility = Literal["public", "private"]
PackageBlockType = Literal["has_blocked_packages", "no_blocked_packages"]
PackageFixType = Literal["has_fix", "no_fix"]
PackageSort = Literal["match", "alphabetical", "usage"]

# --- audit logs --------------------------------------------------------------

AuditLogView = Literal["list", "count"]
SortDirection = Literal["ASC", "DESC"]
AuditLogSortBy = Literal[
    "id",
    "actingUserId",
    "actingUserEmail",
    "actingUserName",
    "actingUserRole",
    "organizationId",
    "userId",
    "teamId",
    "buildId",
    "dependencyId",
    "licenseId",
    "policyId",
    "projectId",
    "ruleId",
    "locator",
    "revisionLicenseId",
    "issueId",
    "action",
    "topic",
    "name",
    "old_value",
    "new_value",
    "description",
    "createdAt",
]

# --- components --------------------------------------------------------------

# The signed-URL endpoint accepts `binary`; the build endpoint does not.
UploadFileType = Literal["archive", "sbom", "binary"]
BuildFileType = Literal["archive", "sbom"]

# --- builds ------------------------------------------------------------------

BuildView = Literal["list", "count"]

# --- SBOM sharing ------------------------------------------------------------

SbomSharingSection = Literal["share_requests", "linked_organizations"]

# --- license conclusions -----------------------------------------------------

LicenseConclusionAction = Literal["conclude", "unconclude"]
LicenseConclusionScope = Literal[
    "project",
    "revision",
    "release_group",
    "release",
    "organization",
    "global",
]

# The exact ids each scope branch of the `oneOf` requires. Anything not listed
# for the selected scope is rejected, so a caller cannot pass a projectLocator
# alongside an organization scope and believe it narrowed anything.
_SCOPE_REQUIRED_FIELDS: dict[LicenseConclusionScope, tuple[str, ...]] = {
    "project": ("project_locator",),
    "revision": ("project_locator", "revision_locator"),
    "release_group": ("release_group_id",),
    "release": ("release_group_id", "release_id"),
    "organization": ("organization_id",),
    "global": (),
}

_SCOPE_FIELD_TO_PAYLOAD_KEY = {
    "project_locator": "projectLocator",
    "revision_locator": "revisionLocator",
    "release_group_id": "releaseGroupId",
    "release_id": "releaseId",
    "organization_id": "organizationId",
}


class BinaryComponentsInput(BaseModel):
    """Input model for fossa_binary_components."""

    model_config = ConfigDict(extra="forbid")

    scope: BinaryScope
    view: BinaryComponentView
    revision_locator: str | None = Field(default=None, min_length=1)
    release_group_id: int | None = Field(default=None, ge=1)
    release_id: int | None = Field(default=None, ge=1)
    path: str | None = None
    search: str | None = None

    @model_validator(mode="after")
    def _validate_scope(self) -> "BinaryComponentsInput":
        if self.scope == "revision":
            if self.revision_locator is None:
                raise ValueError("revision_locator is required for the revision scope")
            if self.release_group_id is not None or self.release_id is not None:
                raise ValueError(
                    "release_group_id and release_id must be None for the revision scope"
                )
        else:
            if self.release_group_id is None or self.release_id is None:
                raise ValueError(
                    "release_group_id and release_id are both required for the release scope"
                )
            if self.revision_locator is not None:
                raise ValueError("revision_locator must be None for the release scope")

        if self.view == "count" and (self.path is not None or self.search is not None):
            raise ValueError("path and search only apply to the paths view")

        return self


class BinaryDependencyConfidenceInput(BaseModel):
    """Input model for fossa_binary_dependency_confidence."""

    model_config = ConfigDict(extra="forbid")

    scope: BinaryScope
    revision_locator: str | None = Field(default=None, min_length=1)
    release_id: int | None = Field(default=None, ge=1)
    dependency_locator: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_scope(self) -> "BinaryDependencyConfidenceInput":
        if self.scope == "revision":
            if self.revision_locator is None:
                raise ValueError("revision_locator is required for the revision scope")
            if self.release_id is not None:
                raise ValueError("release_id must be None for the revision scope")
        else:
            if self.release_id is None:
                raise ValueError("release_id is required for the release scope")
            if self.revision_locator is not None:
                raise ValueError("revision_locator must be None for the release scope")
        return self


class BinaryRevisionDetailInput(BaseModel):
    """Input model for fossa_binary_revision_detail."""

    model_config = ConfigDict(extra="forbid")

    view: BinaryRevisionView
    revision_locator: str = Field(min_length=1)
    component_id: str | None = Field(default=None, min_length=1)
    dependency_locator: str | None = Field(default=None, min_length=1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=50)

    @model_validator(mode="after")
    def _validate_view(self) -> "BinaryRevisionDetailInput":
        if self.view == "component_matches":
            if self.component_id is None:
                raise ValueError("component_id is required for the component_matches view")
            if self.dependency_locator is not None:
                raise ValueError("dependency_locator must be None for the component_matches view")
        else:
            if self.dependency_locator is None:
                raise ValueError(
                    "dependency_locator is required for the dependency_components view"
                )
            if self.component_id is not None:
                raise ValueError("component_id must be None for the dependency_components view")
        return self


class PackageFilters(BaseModel):
    """The filter set shared by `GET /packages` and `GET /packages/report`.

    Both endpoints accept the same fourteen filters; only the list endpoint adds
    pagination and sorting. Keeping them in one base means a filter added to one
    tool cannot silently diverge from the other.
    """

    model_config = ConfigDict(extra="forbid")

    fetchers: list[PackageFetcher] | None = None
    package_name: str | None = None
    depth: list[PackageDepth] | None = None
    labels: list[str] | None = None
    project_name: str | None = None
    sources: list[str] | None = None
    visibility: list[PackageVisibility] | None = None
    block_types: list[PackageBlockType] | None = None
    cve: str | None = None
    cwes: list[str] | None = None
    fix_types: list[PackageFixType] | None = None
    severities: list[Severity] | None = None
    team_ids: list[int] | None = None
    locators: list[str] | None = None


class PackageListInput(PackageFilters):
    """Input model for fossa_list_packages."""

    page: int = Field(default=1, ge=1)
    # FOSSA clamps above 50 rather than erroring; reject instead, so a caller
    # who asks for 200 is told they got 50 rather than discovering it later.
    count: int = Field(default=20, ge=1, le=50)
    sort: PackageSort | None = None


class PackageIndexExportInput(PackageFilters):
    """Input model for fossa_export_package_index."""


class PackageObservabilityInput(BaseModel):
    """Input model for fossa_package_observability."""

    model_config = ConfigDict(extra="forbid")

    section: PackageObservabilitySection
    package_locator: str | None = None
    count: int | None = Field(default=None, ge=1, le=50)

    @model_validator(mode="after")
    def _validate_section(self) -> "PackageObservabilityInput":
        if self.section != "locators" and (
            self.package_locator is not None or self.count is not None
        ):
            raise ValueError("package_locator and count only apply to the locators section")
        return self


class ComponentUploadUrlInput(BaseModel):
    """Input model for fossa_get_component_upload_url."""

    model_config = ConfigDict(extra="forbid")

    package_spec: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    file_type: UploadFileType | None = None


class ResolvePurlsInput(BaseModel):
    """Input model for fossa_resolve_purls."""

    model_config = ConfigDict(extra="forbid")

    purls: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def _validate_purls(self) -> "ResolvePurlsInput":
        if any(not purl.strip() for purl in self.purls):
            raise ValueError("purls must not contain blank entries")
        return self


class ComponentBuildInput(BaseModel):
    """Input model for fossa_build_component.

    The endpoint takes its identity from query parameters and its upload
    metadata from a JSON body that repeats `packageSpec` and `revision`. Both
    are built here from the same two fields so they cannot disagree.
    """

    model_config = ConfigDict(extra="forbid")

    package_spec: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    file_type: BuildFileType | None = None
    dependency: bool | None = None
    description: str | None = None
    branch: str | None = None
    jira_project_key: str | None = None
    link: str | None = None
    project_url: str | None = None
    policy: str | None = None
    policy_id: int | None = Field(default=None, ge=1)
    team: str | None = None
    title: str | None = None
    release_group: str | None = None
    release_group_release: str | None = None
    labels: list[str] | None = None
    selected_team_ids: list[int] | None = None
    selected_team_names: list[str] | None = None
    force_rebuild: bool | None = None

    def to_body(self) -> dict[str, Any]:
        """Build the JSON body, whose `archives` block the spec marks required."""
        archives: dict[str, Any] = {
            "packageSpec": self.package_spec,
            "revision": self.revision,
        }
        if self.description is not None:
            archives["description"] = self.description
        if self.project_url is not None:
            archives["projectURL"] = self.project_url

        body: dict[str, Any] = {"archives": archives}

        selected_teams: list[dict[str, Any]] = [
            {"id": team_id} for team_id in self.selected_team_ids or []
        ]
        selected_teams.extend({"name": name} for name in self.selected_team_names or [])
        if selected_teams:
            body["selectedTeams"] = selected_teams

        if self.force_rebuild is not None:
            body["forceRebuild"] = self.force_rebuild

        return body


class AuditLogReadInput(BaseModel):
    """Input model for fossa_get_audit_logs."""

    model_config = ConfigDict(extra="forbid")

    view: AuditLogView = "list"
    offset: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, ge=1)
    sort_by: AuditLogSortBy | None = None
    sort_dir: SortDirection | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    acting_user_ids: list[str] | None = None
    actions: list[str] | None = None
    topics: list[str] | None = None
    topic_actions: list[str] | None = None
    starting_after: str | None = None
    ending_before: str | None = None


class AuditLogExportInput(BaseModel):
    """Input model for fossa_export_audit_logs."""

    model_config = ConfigDict(extra="forbid")

    start_date: date
    end_date: date
    acting_user_ids: list[str] | None = None
    actions: list[str] | None = None
    topics: list[str] | None = None
    topic_actions: list[str] | None = None

    @model_validator(mode="after")
    def _validate_range(self) -> "AuditLogExportInput":
        if self.end_date < self.start_date:
            raise ValueError("end_date must not be earlier than start_date")
        return self


class SbomSharingReadInput(BaseModel):
    """Input model for fossa_get_sbom_sharing."""

    model_config = ConfigDict(extra="forbid")

    section: SbomSharingSection = "share_requests"
    project_locator: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_section(self) -> "SbomSharingReadInput":
        if self.section != "share_requests" and self.project_locator is not None:
            raise ValueError("project_locator only applies to the share_requests section")
        return self


class SbomShareInput(BaseModel):
    """Input model for fossa_share_sbom_revision."""

    model_config = ConfigDict(extra="forbid")

    revision_id: str = Field(min_length=1)
    shared_organization_id: int = Field(ge=1)


class LicenseConclusionInput(BaseModel):
    """Input model for fossa_set_license_conclusion.

    `scope` is required and has no default. FOSSA's `oneOf` offers six branches
    and two of them — `organization` and `global` — apply to every project in
    the organization (or, for `global`, FOSSA's whole corpus). Defaulting to
    either would let an unqualified call silently re-license an org, so the
    caller must always say which one they mean and supply that branch's ids.
    """

    model_config = ConfigDict(extra="forbid")

    action: LicenseConclusionAction
    dependency_revision_locator: str = Field(min_length=1)
    scope: LicenseConclusionScope
    license_id: str = Field(min_length=1)
    project_locator: str | None = Field(default=None, min_length=1)
    revision_locator: str | None = Field(default=None, min_length=1)
    release_group_id: int | None = Field(default=None, ge=1)
    release_id: int | None = Field(default=None, ge=1)
    organization_id: int | None = Field(default=None, ge=1)
    origin_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate_scope(self) -> "LicenseConclusionInput":
        required = _SCOPE_REQUIRED_FIELDS[self.scope]
        for field_name in required:
            if getattr(self, field_name) is None:
                raise ValueError(f"{field_name} is required for the {self.scope} scope")

        for field_name in _SCOPE_FIELD_TO_PAYLOAD_KEY:
            if field_name not in required and getattr(self, field_name) is not None:
                raise ValueError(f"{field_name} must be None for the {self.scope} scope")

        return self

    @property
    def scope_payload(self) -> dict[str, Any]:
        """Build the `scope` object for the branch of the `oneOf` selected."""
        payload: dict[str, Any] = {"scope": self.scope}
        for field_name in _SCOPE_REQUIRED_FIELDS[self.scope]:
            payload[_SCOPE_FIELD_TO_PAYLOAD_KEY[field_name]] = getattr(self, field_name)
        return payload

    @property
    def affects_whole_organization(self) -> bool:
        """True when the conclusion applies past a single project or release."""
        return self.scope in ("organization", "global")

    def to_body(self) -> dict[str, Any]:
        """Build the request body both `conclude` and `unconclude` accept."""
        body: dict[str, Any] = {
            "dependencyRevisionLocator": self.dependency_revision_locator,
            "scope": self.scope_payload,
            "licenseId": self.license_id,
        }
        if self.origin_id is not None:
            body["originId"] = self.origin_id
        return body


class BuildReadInput(BaseModel):
    """Input model for fossa_get_builds."""

    model_config = ConfigDict(extra="forbid")

    view: BuildView = "list"
    locator: str | None = Field(default=None, min_length=1)
    project_id: str | None = Field(default=None, min_length=1)
    start_date: datetime | None = None
    end_date: datetime | None = None
    page: int | None = Field(default=None, ge=1)
    page_size: int | None = Field(default=None, ge=1)
    sort: str | None = Field(default=None, min_length=1)


class CveSearchInput(BaseModel):
    """Input model for fossa_search_cves."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1)


class VulnerabilityRemediationInput(BaseModel):
    """Input model for fossa_get_vulnerability_remediation."""

    model_config = ConfigDict(extra="forbid")

    vuln_id: str = Field(min_length=1)
    revision_id: str = Field(min_length=1)
