"""Input models for the release group tools.

Every path parameter in this domain is a numeric surrogate id — a release group
id and, under it, a release id — never a slug or a locator. They are validated
with `ge=1` so a `0` or a negative never reaches FOSSA as a path segment.

The one place FOSSA locators do appear is inside a release's project list, where
`projectId` is a project locator and `projectsToDelete` is a list of them. Those
are body values, not path segments, so they are sent as-is without percent
encoding.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Sections of a release group that can be fetched in one call. Each maps to a
# distinct FOSSA endpoint; the Literal is what keeps an invalid section a schema
# error at the client instead of a 404 from FOSSA.
ReleaseGroupSection = Literal["group", "teams", "projects"]
RELEASE_GROUP_SECTION_ORDER: tuple[ReleaseGroupSection, ...] = ("group", "teams", "projects")

ReleaseSection = Literal["release", "summary", "licenses", "obligations", "revisions", "scans"]
RELEASE_SECTION_ORDER: tuple[ReleaseSection, ...] = (
    "release",
    "summary",
    "licenses",
    "obligations",
    "revisions",
    "scans",
)

# The attribution formats FOSSA accepts for a release group release.
ReleaseGroupReportFormat = Literal[
    "HTML",
    "MD",
    "PDF",
    "CSV",
    "TXT",
    "SPDX",
    "SPDX_JSON",
    "CYCLONEDX_JSON",
    "CYCLONEDX_XML",
]

# The subset that survives being returned to an MCP client as text. PDF is
# excluded deliberately: the synchronous download path decodes the response
# body as text, which would corrupt it. Ask for PDF through the queued report
# instead, which hands back a URL.
ReleaseGroupTextReportFormat = Literal[
    "HTML",
    "MD",
    "CSV",
    "TXT",
    "SPDX",
    "SPDX_JSON",
    "CYCLONEDX_JSON",
    "CYCLONEDX_XML",
]

# The two attribution endpoints publish different option sets; v2 added
# ConcludedLicense, Copyrights, and LicenseFileURL.
AttributionDependencyInfoOption = Literal[
    "Project",
    "Library",
    "Authors",
    "Description",
    "License",
    "CustomTextLicense",
    "FullTextLicense",
    "OtherLicenses",
    "FilePath",
    "Source",
    "ProjectUrl",
    "PackageDownloadUrl",
    "DependencyPaths",
    "IssueNotes",
]

AttributionDependencyInfoOptionV2 = Literal[
    "Project",
    "Library",
    "Authors",
    "Description",
    "ConcludedLicense",
    "License",
    "CustomTextLicense",
    "FullTextLicense",
    "OtherLicenses",
    "FilePath",
    "Source",
    "ProjectUrl",
    "PackageDownloadUrl",
    "DependencyPaths",
    "IssueNotes",
    "Copyrights",
    "LicenseFileURL",
]

# Release group fields FOSSA documents as nullable. A flat tool signature cannot
# tell "leave this alone" from "set this to null", because both arrive as None,
# so clearing is a separate explicit list.
ReleaseGroupClearableField = Literal[
    "licensingPolicyId",
    "securityPolicyId",
    "qualityPolicyId",
    "reportCustomText",
]

_CLEARABLE_TO_PARAMETER = {
    "licensingPolicyId": "licensing_policy_id",
    "securityPolicyId": "security_policy_id",
    "qualityPolicyId": "quality_policy_id",
    "reportCustomText": "report_custom_text",
}


class ReleaseProject(BaseModel):
    """One project pinned into a release.

    The field names are FOSSA's body keys verbatim, so a validated instance
    dumps straight into the request body with no translation step.
    """

    model_config = ConfigDict(extra="forbid")

    projectId: str = Field(min_length=1)  # noqa: N815 - FOSSA body key
    branch: str | None = Field(default=None, min_length=1)
    revisionId: str | None = Field(default=None, min_length=1)  # noqa: N815 - FOSSA body key


def _ordered_unique(values: list[str], order: tuple[str, ...]) -> list[str]:
    """Return `values` deduplicated and sorted into canonical `order`.

    Section order decides both the sequence of HTTP calls and the reported
    endpoint string, so it must not depend on the order the caller happened to
    list them in.
    """
    requested = set(values)
    return [section for section in order if section in requested]


class ReleaseGroupReadInput(BaseModel):
    """Input model for fossa_get_release_group."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    sections: list[ReleaseGroupSection] = Field(min_length=1)

    @model_validator(mode="after")
    def _normalize_sections(self) -> "ReleaseGroupReadInput":
        self.sections = _ordered_unique(  # type: ignore[assignment]
            list(self.sections), RELEASE_GROUP_SECTION_ORDER
        )
        return self


class ReleaseGroupReleaseListInput(BaseModel):
    """Input model for fossa_list_release_group_releases."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    page: int = Field(default=1, ge=1)
    # FOSSA caps this endpoint at 50, well below the server's own page ceiling.
    count: int = Field(default=10, ge=1, le=50)
    search: str | None = Field(default=None, min_length=1)


class ReleaseReadInput(BaseModel):
    """Input model for fossa_get_release_group_release."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    release_id: int = Field(ge=1)
    sections: list[ReleaseSection] = Field(min_length=1)

    @model_validator(mode="after")
    def _normalize_sections(self) -> "ReleaseReadInput":
        self.sections = _ordered_unique(  # type: ignore[assignment]
            list(self.sections), RELEASE_SECTION_ORDER
        )
        return self


class AttributionTaskStatusInput(BaseModel):
    """Input model for fossa_get_release_group_attribution_status."""

    model_config = ConfigDict(extra="forbid")

    task_id: int = Field(ge=1)


class ReleaseGroupCreateInput(BaseModel):
    """Input model for fossa_create_release_group.

    FOSSA will not create an empty release group: the create endpoint requires
    an initial release, so `release_title` and `projects` are required here too.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    release_title: str = Field(min_length=1)
    projects: list[ReleaseProject] = Field(min_length=1)
    licensing_policy_id: int | None = Field(default=None, ge=1)
    security_policy_id: int | None = Field(default=None, ge=1)
    quality_policy_id: int | None = Field(default=None, ge=1)
    public_on_portal: bool | None = None
    team_ids: list[int] | None = None

    @model_validator(mode="after")
    def _check_team_ids(self) -> "ReleaseGroupCreateInput":
        if self.team_ids is not None:
            if not self.team_ids:
                raise ValueError("team_ids must name at least one team when provided")
            if any(team_id < 1 for team_id in self.team_ids):
                raise ValueError("team_ids must all be >= 1")
        return self


class ReleaseGroupUpdateInput(BaseModel):
    """Input model for fossa_update_release_group."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1)
    licensing_policy_id: int | None = Field(default=None, ge=1)
    security_policy_id: int | None = Field(default=None, ge=1)
    quality_policy_id: int | None = Field(default=None, ge=1)
    public_on_portal: bool | None = None
    report_custom_text: str | None = None
    clear_fields: list[ReleaseGroupClearableField] | None = None

    @model_validator(mode="after")
    def _check_something_changes(self) -> "ReleaseGroupUpdateInput":
        assigned = [
            name
            for name in (
                "title",
                "licensing_policy_id",
                "security_policy_id",
                "quality_policy_id",
                "public_on_portal",
                "report_custom_text",
            )
            if getattr(self, name) is not None
        ]
        cleared = self.clear_fields or []

        if not assigned and not cleared:
            raise ValueError(
                "Provide at least one field to update, or name a field in clear_fields"
            )

        conflicts = [field for field in cleared if _CLEARABLE_TO_PARAMETER[field] in assigned]
        if conflicts:
            raise ValueError(f"Cannot set and clear the same field: {', '.join(sorted(conflicts))}")

        return self


class ReleaseGroupDeleteInput(BaseModel):
    """Input model for fossa_delete_release_group."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)


class ReleaseCreateInput(BaseModel):
    """Input model for fossa_create_release_group_release."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    title: str = Field(min_length=1)
    projects: list[ReleaseProject] = Field(min_length=1)


class ReleaseUpdateInput(BaseModel):
    """Input model for fossa_update_release_group_release.

    FOSSA requires `title` on this endpoint even when only the project list is
    changing, so it is required here rather than optional.
    """

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    release_id: int = Field(ge=1)
    title: str = Field(min_length=1)
    projects: list[ReleaseProject] | None = None
    projects_to_delete: list[str] | None = None

    @model_validator(mode="after")
    def _check_project_lists(self) -> "ReleaseUpdateInput":
        if self.projects is not None and not self.projects:
            raise ValueError("projects must name at least one project when provided")

        removals = self.projects_to_delete
        if removals is not None:
            if not removals:
                raise ValueError("projects_to_delete must name at least one project when provided")
            if any(not locator.strip() for locator in removals):
                raise ValueError("projects_to_delete must not contain blank entries")

            added = {project.projectId for project in (self.projects or [])}
            overlap = sorted(added.intersection(removals))
            if overlap:
                raise ValueError(
                    "A project cannot be added and removed in the same update: "
                    f"{', '.join(overlap)}"
                )

        return self


class ReleaseDeleteInput(BaseModel):
    """Input model for fossa_delete_release_group_release."""

    model_config = ConfigDict(extra="forbid")

    release_group_id: int = Field(ge=1)
    release_id: int = Field(ge=1)


class AttributionOptions(BaseModel):
    """The report content switches both attribution endpoints share.

    Defaults match `fossa_get_attribution_report` so the same request produces
    comparable output for a revision and for a release.
    """

    model_config = ConfigDict(extra="forbid")

    include_deep_dependencies: bool = True
    include_direct_dependencies: bool = True
    include_fossa_dependencies: bool = False
    include_license_list: bool = True
    include_license_scan: bool = False
    include_project_license: bool = True
    include_copyright_list: bool = False
    include_file_matches: bool = False
    include_open_vulnerabilities: bool = False
    include_closed_vulnerabilities: bool = False
    include_dependency_summary: bool = True
    include_license_headers: bool = False


class ReleaseGroupAttributionInput(AttributionOptions):
    """Input model for fossa_get_release_group_attribution_report."""

    release_group_id: int = Field(ge=1)
    release_id: int = Field(ge=1)
    format: ReleaseGroupTextReportFormat = "MD"
    preview: bool = False
    include_package_labels: bool = False
    dependency_info_options: list[AttributionDependencyInfoOptionV2] | None = None
    exclude_package_labels: list[str] | None = None
    release_group_title: str | None = Field(default=None, min_length=1)
    release_title: str | None = Field(default=None, min_length=1)
    release_group_url: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _check_exclusions(self) -> "ReleaseGroupAttributionInput":
        labels = self.exclude_package_labels
        if labels is not None:
            if not labels:
                raise ValueError(
                    "exclude_package_labels must name at least one label when provided"
                )
            if any(not label.strip() for label in labels):
                raise ValueError("exclude_package_labels must not contain blank entries")
        return self


class ReleaseGroupAttributionQueueInput(AttributionOptions):
    """Input model for fossa_queue_release_group_attribution_report."""

    release_group_id: int = Field(ge=1)
    release_id: int = Field(ge=1)
    format: ReleaseGroupReportFormat = "MD"
    is_publishing: bool = False
    dependency_info_options: list[AttributionDependencyInfoOption] | None = None
