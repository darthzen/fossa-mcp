"""Input models for the integration and configuration tools.

Five FOSSA domains share this module because they share one shape: they
configure FOSSA rather than describe a codebase. Jira sites, fossabot
dependency-upgrade PRs, saved report options, custom risk scores, and snippet
review state.

Three things about this domain are worth stating up front:

* **Jira configuration carries credentials.** `credentials.basic.password` and
  the arbitrary `headers` map are both secrets, and `webhookURL` is a capability
  URL that authenticates whoever holds it. They can be *sent* — otherwise the
  integration cannot be configured at all — but nothing here ever returns one;
  see `tools/integrations.py` for the redaction.
* **`customRiskScore` here is FOSSA's own field**, the score stored against a
  vulnerability issue in a project or release-group scope. It is unrelated to
  the independent impact score computed by this repo's `fossa-suggest-score`
  skill, which never writes to FOSSA.
* **Snippet query arrays carry no `[]` suffix.** Everywhere FOSSA wants the
  bracketed `qs` form the vendored spec names the parameter with the brackets
  in it (`locators[]`, `depth[]`). The snippet parameters are named `ids`,
  `packageIds`, `rejectionStatus`, `packageLabels` and `vendoredMatch`, so they
  are repeated as plain keys.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- Jira --------------------------------------------------------------------

# Jira configuration fields FOSSA documents as nullable. A flat tool signature
# cannot tell "leave this alone" from "set this to null" because both arrive as
# None, so clearing is a separate explicit list — the same treatment release
# groups get.
JiraClearableField = Literal[
    "base_url",
    "headers",
    "issueTypes",
    "labels",
    "components",
    "jiraProjectIds",
    "customFields",
    "defaultLicensingProject",
    "defaultSecurityProject",
    "defaultQualityProject",
]

_JIRA_CLEARABLE_TO_PARAMETER = {
    "base_url": "base_url",
    "headers": "headers",
    "issueTypes": "issue_types",
    "labels": "labels",
    "components": "components",
    "jiraProjectIds": "jira_project_ids",
    "customFields": "custom_fields",
    "defaultLicensingProject": "default_licensing_project",
    "defaultSecurityProject": "default_security_project",
    "defaultQualityProject": "default_quality_project",
}


class JiraComponent(BaseModel):
    """One Jira component offered when exporting a ticket.

    Field names are FOSSA's body keys verbatim, so a validated instance dumps
    straight into the request body.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    displayName: str = Field(min_length=1)  # noqa: N815 - FOSSA body key


class JiraCustomField(BaseModel):
    """One Jira custom field offered when exporting a ticket."""

    model_config = ConfigDict(extra="forbid")

    fieldId: str = Field(min_length=1)  # noqa: N815 - FOSSA body key
    displayName: str = Field(min_length=1)  # noqa: N815 - FOSSA body key
    isRequired: bool = False  # noqa: N815 - FOSSA body key
    defaultValue: str | None = None  # noqa: N815 - FOSSA body key


class JiraConfigurationSaveInput(BaseModel):
    """Input model for fossa_save_jira_configuration.

    One model for both `POST /jira` and `PATCH /jira/{id}`: the request bodies
    are identical and only the presence of `jira_id` decides which is sent.
    """

    model_config = ConfigDict(extra="forbid")

    jira_id: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    base_url: str | None = Field(default=None, min_length=1)
    resolved_statuses: list[str] | None = None
    resolved_statuses_enabled: bool | None = None
    username: str | None = Field(default=None, min_length=1)
    password: str | None = Field(default=None, min_length=1)
    headers: dict[str, str] | None = None
    issue_types: list[str] | None = None
    labels: list[str] | None = None
    components: list[JiraComponent] | None = None
    jira_project_ids: list[str] | None = None
    custom_fields: dict[str, JiraCustomField] | None = None
    default_licensing_project: str | None = Field(default=None, min_length=1)
    default_security_project: str | None = Field(default=None, min_length=1)
    default_quality_project: str | None = Field(default=None, min_length=1)
    default_unique_tickets: bool | None = None
    clear_fields: list[JiraClearableField] | None = None

    _ASSIGNABLE = (
        "name",
        "enabled",
        "base_url",
        "resolved_statuses",
        "resolved_statuses_enabled",
        "headers",
        "issue_types",
        "labels",
        "components",
        "jira_project_ids",
        "custom_fields",
        "default_licensing_project",
        "default_security_project",
        "default_quality_project",
        "default_unique_tickets",
    )

    @model_validator(mode="after")
    def _check_shape(self) -> "JiraConfigurationSaveInput":
        if (self.username is None) != (self.password is None):
            raise ValueError("username and password must be provided together")

        if self.jira_id is None and not self.name:
            raise ValueError("name is required when creating a Jira configuration")

        assigned = [name for name in self._ASSIGNABLE if getattr(self, name) is not None]
        if self.username is not None:
            assigned.append("credentials")

        cleared = self.clear_fields or []
        if self.jira_id is not None and not assigned and not cleared:
            raise ValueError(
                "Provide at least one field to update, or name a field in clear_fields"
            )

        conflicts = [field for field in cleared if _JIRA_CLEARABLE_TO_PARAMETER[field] in assigned]
        if conflicts:
            raise ValueError(f"Cannot set and clear the same field: {', '.join(sorted(conflicts))}")

        for name in ("resolved_statuses", "issue_types", "labels", "jira_project_ids"):
            values = getattr(self, name)
            if values is not None and any(not value.strip() for value in values):
                raise ValueError(f"{name} must not contain blank entries")

        return self


class JiraConfigurationDeleteInput(BaseModel):
    """Input model for fossa_delete_jira_configuration."""

    model_config = ConfigDict(extra="forbid")

    jira_id: int = Field(ge=1)


# --- fossabot ----------------------------------------------------------------

FossabotPRState = Literal["open", "draft", "closed", "merged"]
FossabotPRSort = Literal["newest", "oldest"]
FossabotFix = Literal["partial", "complete"]


class FossabotStatusInput(BaseModel):
    """Input model for fossa_get_fossabot_status."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str | None = Field(default=None, min_length=1)


class FossabotUpgradePRListInput(BaseModel):
    """Input model for fossa_list_fossabot_upgrade_prs.

    The endpoint is cursor-paginated in the Relay style: `first`/`after` walks
    forward and `last`/`before` walks backward, and the two directions cannot be
    mixed.
    """

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    first: int | None = Field(default=None, ge=1)
    after: str | None = Field(default=None, min_length=1)
    last: int | None = Field(default=None, ge=1)
    before: str | None = Field(default=None, min_length=1)
    state: FossabotPRState | None = None
    search: str | None = Field(default=None, min_length=1)
    sort: FossabotPRSort | None = None
    include_counts: bool = False

    @model_validator(mode="after")
    def _check_cursor_direction(self) -> "FossabotUpgradePRListInput":
        forward = self.first is not None or self.after is not None
        backward = self.last is not None or self.before is not None
        if forward and backward:
            raise ValueError("Use first/after or last/before, not both")
        if self.after is not None and self.first is None:
            raise ValueError("after requires first")
        if self.before is not None and self.last is None:
            raise ValueError("before requires last")
        return self


class FossabotIssuePRInput(BaseModel):
    """Input model for fossa_get_fossabot_upgrade_pr."""

    model_config = ConfigDict(extra="forbid")

    issue_id: int = Field(ge=1)
    project_locator: str | None = Field(default=None, min_length=1)
    job_id: str | None = Field(default=None, min_length=1)


class FossabotUpgradePRRequestInput(BaseModel):
    """Input model for fossa_request_fossabot_upgrade_pr."""

    model_config = ConfigDict(extra="forbid")

    issue_id: int = Field(ge=1)
    project_locator: str | None = Field(default=None, min_length=1)
    fix: FossabotFix | None = None
    retry_analysis: bool = False

    @model_validator(mode="after")
    def _check_retry(self) -> "FossabotUpgradePRRequestInput":
        if self.retry_analysis and self.fix is not None:
            raise ValueError("fix applies to creating a PR, not to retrying its analysis")
        return self


# --- report options ----------------------------------------------------------

ReportOptionSection = Literal[
    "projectDeclaredLicenses",
    "firstPartyLicenses",
    "licenseList",
    "directDependencies",
    "deepDependencies",
    "snippetDependencies",
    "copyrightList",
]
REPORT_OPTION_SECTIONS: tuple[ReportOptionSection, ...] = (
    "projectDeclaredLicenses",
    "firstPartyLicenses",
    "licenseList",
    "directDependencies",
    "deepDependencies",
    "snippetDependencies",
    "copyrightList",
)

ReportOptionDependencyField = Literal[
    "projects",
    "authors",
    "description",
    "homepage",
    "packageManager",
    "downloadUrl",
    "concludedLicenses",
    "declaredLicenses",
    "discoveredLicenses",
    "copyrights",
    "licenseUrl",
    "licenseFileMatches",
    "issueResolutionNotes",
    "packageLabels",
    "dependencyPaths",
    "filePaths",
    "noticeFiles",
    "fullLicenseText",
]
REPORT_OPTION_DEPENDENCY_FIELDS: tuple[ReportOptionDependencyField, ...] = (
    "projects",
    "authors",
    "description",
    "homepage",
    "packageManager",
    "downloadUrl",
    "concludedLicenses",
    "declaredLicenses",
    "discoveredLicenses",
    "copyrights",
    "licenseUrl",
    "licenseFileMatches",
    "issueResolutionNotes",
    "packageLabels",
    "dependencyPaths",
    "filePaths",
    "noticeFiles",
    "fullLicenseText",
)


class ReportOptionSaveInput(BaseModel):
    """Input model for fossa_save_report_option.

    FOSSA's body nests 26 independent booleans under `options`. Rather than 26
    tri-state parameters, `sections` and `dependency_data` name the switches
    that should be **on**; every switch in the group is then sent explicitly,
    with the unnamed ones off. A group left as None is omitted entirely, which
    is what makes a partial update possible — `PUT /report-options/{id}` deep
    merges.

    `POST /report-options` requires all four groups, so a create with any of
    them missing is rejected here rather than by FOSSA.
    """

    model_config = ConfigDict(extra="forbid")

    report_option_id: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=80)
    sections: list[ReportOptionSection] | None = None
    dependency_data: list[ReportOptionDependencyField] | None = None
    use_hash_and_version_data: bool | None = None
    exclude_package_labels: list[int] | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> "ReportOptionSaveInput":
        if self.exclude_package_labels is not None and any(
            label < 1 for label in self.exclude_package_labels
        ):
            raise ValueError("exclude_package_labels must all be >= 1")

        groups = {
            "sections": self.sections,
            "dependency_data": self.dependency_data,
            "use_hash_and_version_data": self.use_hash_and_version_data,
            "exclude_package_labels": self.exclude_package_labels,
        }

        if self.report_option_id is None:
            if not self.name:
                raise ValueError("name is required when creating a report option")
            missing = sorted(key for key, value in groups.items() if value is None)
            if missing:
                raise ValueError(
                    "Creating a report option requires every option group: "
                    f"missing {', '.join(missing)}"
                )
        elif self.name is None and all(value is None for value in groups.values()):
            raise ValueError("Provide a name or at least one option group to update")

        return self


class ReportOptionDeleteInput(BaseModel):
    """Input model for fossa_delete_report_option."""

    model_config = ConfigDict(extra="forbid")

    report_option_id: int = Field(ge=1)


# --- custom risk scores ------------------------------------------------------

RiskScoreScope = Literal["project", "release_group"]
RiskScoreAction = Literal["create", "update"]


class CustomRiskScoreSaveInput(BaseModel):
    """Input model for fossa_set_custom_risk_score.

    `action` is explicit rather than inferred: FOSSA publishes no endpoint that
    reads a custom risk score back, so the tool cannot discover whether one
    already exists, and guessing would turn a wrong guess into a 4xx.
    """

    model_config = ConfigDict(extra="forbid")

    action: RiskScoreAction
    issue_id: int = Field(ge=1)
    scope_type: RiskScoreScope
    scope_id: str = Field(min_length=1)
    score: int = Field(ge=0, le=100)
    reason: str | None = Field(default=None, min_length=1, max_length=500)


class CustomRiskScoreDeleteInput(BaseModel):
    """Input model for fossa_delete_custom_risk_score."""

    model_config = ConfigDict(extra="forbid")

    issue_id: int = Field(ge=1)
    scope_type: RiskScoreScope
    scope_id: str = Field(min_length=1)


# --- snippets ----------------------------------------------------------------

SnippetView = Literal["snippets", "packages", "paths", "count"]
SnippetChangeStatus = Literal["new", "removed", "unchanged"]
SnippetRejectionStatus = Literal["rejected", "unrejected"]
SnippetVendoredMatch = Literal["vendored", "exVendored", "converted", "exConverted"]
SnippetSort = Literal["package_asc", "package_desc", "matchCount_asc", "matchCount_desc"]


class SnippetFilters(BaseModel):
    """The filter set every snippet endpoint accepts, query or body.

    `path` is required by FOSSA on every one of them except `paths`, which
    aggregates from the root when it is omitted.
    """

    model_config = ConfigDict(extra="forbid")

    path: str | None = Field(default=None, min_length=1)
    snippet_ids: list[str] | None = None
    package_ids: list[str] | None = None
    search: str | None = Field(default=None, min_length=1)
    rejection_status: list[SnippetRejectionStatus] | None = None
    package_labels: list[str] | None = None
    vendored_match: list[SnippetVendoredMatch] | None = None

    @model_validator(mode="after")
    def _check_lists(self) -> "SnippetFilters":
        for name in ("snippet_ids", "package_ids", "package_labels"):
            values = getattr(self, name)
            if values is not None:
                if not values:
                    raise ValueError(f"{name} must name at least one value when provided")
                if any(not value.strip() for value in values):
                    raise ValueError(f"{name} must not contain blank entries")
        return self

    @property
    def names_an_explicit_target_set(self) -> bool:
        """Whether the filter names individual snippets rather than a shape."""
        return bool(self.snippet_ids or self.package_ids)


class SnippetListInput(SnippetFilters):
    """Input model for fossa_list_snippets."""

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    view: SnippetView = "snippets"
    compare_to_revision: str | None = Field(default=None, min_length=1)
    change_status: SnippetChangeStatus | None = None
    sort: SnippetSort | None = None
    page: int = Field(default=1, ge=1)
    # FOSSA caps this endpoint family at 50, below the server's own ceiling.
    page_size: int = Field(default=10, ge=1, le=50)

    @model_validator(mode="after")
    def _check_view(self) -> "SnippetListInput":
        if (self.compare_to_revision is None) != (self.change_status is None):
            raise ValueError(
                "compare_to_revision and change_status must be set together or both unset"
            )
        if self.compare_to_revision is not None and self.view == "count":
            raise ValueError("FOSSA has no snippet count endpoint for a revision comparison")
        if self.view != "paths" and self.path is None:
            raise ValueError(f"path is required for the {self.view} view")
        return self


class SnippetReadInput(BaseModel):
    """Input model for fossa_get_snippet."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    snippet_id: str = Field(min_length=1)
    path: str | None = Field(default=None, min_length=1)
    include_match_details: bool = False

    @model_validator(mode="after")
    def _check_match_details(self) -> "SnippetReadInput":
        if self.include_match_details and self.path is None:
            raise ValueError("include_match_details needs the path of the match to read")
        return self


class SnippetRejectionInput(SnippetFilters):
    """Input model for fossa_set_snippet_rejection."""

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    rejected: bool

    @model_validator(mode="after")
    def _check_path(self) -> "SnippetRejectionInput":
        if self.path is None:
            raise ValueError("path is required: FOSSA scopes a rejection to a subtree")
        return self
