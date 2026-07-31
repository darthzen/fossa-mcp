"""Input models for the issue, issue overview, and issue filter tools.

The shared `Literal` aliases these build on (`IssueCategory`, `IssueStatus`,
`Severity`, `ScopeType`, and friends) live in the package namespace and are
imported here rather than redefined. Everything new to the issue domain is
declared below.

Two FOSSA behaviors shape most of the cross-field rules:

* Every issue endpoint is scoped. `scope[type]=global` must not carry a project
  locator, and `scope[type]=project` requires both a project and a revision.
  The `releaseGroup` scope FOSSA also accepts is not exposed by these tools.
* Several endpoints reject a `category` they do not apply to. `GET
  /v2/issues/license-list` only accepts `licensing`; `GET /v2/issues/categories`
  and `/types` accept no category at all. Those are schema errors here rather
  than a 400 from FOSSA.
"""

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import (
    ChangeStatus,
    IssueCategory,
    IssueDepth,
    IssueStatus,
    ScopeType,
    Severity,
    SeveritySource,
)

# Which facet endpoint under /v2/issues to read. Each is a different aggregation
# of the same issue set, so they are one tool with a validated selector rather
# than six near-identical tools.
IssueFacet = Literal[
    "categories",
    "cwes",
    "license-list",
    "package-managers",
    "statuses",
    "types",
]

# Facets that require a category, take an optional one, or reject it outright.
FACETS_REQUIRING_CATEGORY = frozenset({"license-list", "package-managers", "statuses"})
FACETS_REJECTING_CATEGORY = frozenset({"categories", "cwes", "types"})
FACETS_ACCEPTING_STATUS = frozenset({"cwes", "package-managers"})

IssueRevisionSort = Literal[
    "package_asc",
    "package_desc",
    "created_at_asc",
    "created_at_desc",
    "issue_count_asc",
    "issue_count_desc",
    "epss_asc",
    "epss_desc",
]

# The five body variants of PUT /v2/issues, minus `export`. See
# `IssueUpdateInput` for why the export variant is not offered.
IssueUpdateAction = Literal["ignore", "unignore", "unlink", "issueException"]

# FOSSA maps these onto CycloneDX VEX statuses: `Fixed` and
# `Under_investigation` keep their names, everything else becomes
# `Not Affected`.
IgnoreReason = Literal[
    "Fixed",
    "Under_investigation",
    "Vulnerable_code_not_present",
    "Vulnerable_code_cannot_be_controlled",
    "Component_not_present",
    "Vulnerable_code_not_in_execute_path",
    "Inline_mitigations_already_exist",
    "incorrect_data_found",
    "other",
]

PackageScope = Literal["SELECTED_VERSION", "ALL_VERSIONS"]
IgnoreScope = Literal[
    "ORGANIZATION",
    "POLICY",
    "PROJECT",
    "RELEASE_GROUP",
    "PROJECT_AND_RELEASE_GROUPS",
]

DisputeReason = Literal[
    "INCORRECT_DEPENDENCY_VERSION_REPORTED",
    "LICENSE_DETECTION_FALSE_POSITIVE",
    "MULTI_OR_DUAL_LICENSED",
    "INCORRECT_LICENSE_CONCLUSION",
    "INCORRECT_STALENESS_REPORTED",
    "INCORRECTLY_FLAGGED_ABANDONWARE",
    "INCORRECTLY_FLAGGED_EMPTY",
]

ExceptionSortBy = Literal["id", "package", "created_by", "scope"]
SortOrder = Literal["asc", "desc"]

# The filter form of DELETE /v2/issues/exceptions only accepts one category.
ExceptionDeleteCategory = Literal["licensing"]

IssueFilterSort = Literal[
    "severity_asc",
    "severity_desc",
    "issue_count_asc",
    "issue_count_desc",
    "created_at_asc",
    "created_at_desc",
    "package_asc",
    "package_desc",
    "epss_asc",
    "epss_desc",
]
IssueFilterGroup = Literal["issue", "revision"]

# Fields that narrow a bulk action's target set. Kept at module level rather
# than on the model, because a leading-underscore class attribute on a pydantic
# model becomes a private attribute rather than a plain constant.
_UPDATE_FILTER_FIELDS = (
    "search",
    "depths",
    "issue_types",
    "package_managers",
    "cwes",
    "project_labels",
    "licenses",
    "severity",
    "severity_source",
    "revision_ids",
    "found_after",
)

_EXCEPTION_FILTER_FIELDS = ("category", "project_id", "release_group_id", "policy_id")


class IssueScopeInput(BaseModel):
    """Base for the issue inputs that carry a FOSSA issue scope."""

    model_config = ConfigDict(extra="forbid")

    scope_type: ScopeType = "global"
    project_locator: str | None = None
    revision_locator: str | None = None

    @model_validator(mode="after")
    def _validate_issue_scope(self) -> "IssueScopeInput":
        if self.scope_type == "global":
            if self.project_locator is not None:
                raise ValueError("project_locator must be None for global scope")
            if self.revision_locator is not None:
                raise ValueError("revision_locator must be None for global scope")
        else:
            if self.project_locator is None:
                raise ValueError("project_locator is required for project scope")
            if self.revision_locator is None:
                raise ValueError("revision_locator is required for project scope")
        return self


class IssueFacetInput(IssueScopeInput):
    """Input model for fossa_get_issue_facets."""

    facet: IssueFacet
    category: IssueCategory | None = None
    status: IssueStatus | None = None
    team_ids: list[str] | None = None

    @model_validator(mode="after")
    def _validate_facet_arguments(self) -> "IssueFacetInput":
        if self.facet in FACETS_REJECTING_CATEGORY:
            if self.category is not None:
                raise ValueError(f"category is not accepted by the {self.facet} facet")
        elif self.category is None:
            raise ValueError(f"category is required for the {self.facet} facet")

        if self.facet == "license-list" and self.category != "licensing":
            raise ValueError("the license-list facet only applies to the licensing category")

        if self.status is not None and self.facet not in FACETS_ACCEPTING_STATUS:
            raise ValueError(f"status is not accepted by the {self.facet} facet")

        return self


class IssueRevisionListInput(IssueScopeInput):
    """Input model for fossa_list_issue_revisions."""

    category: IssueCategory
    status: IssueStatus = "active"
    compare_to_revision: str | None = None
    change_status: ChangeStatus | None = None
    issue_ids: list[int] | None = None
    search: str | None = None
    depths: list[IssueDepth] | None = None
    issue_types: list[str] | None = None
    package_managers: list[str] | None = None
    project_labels: list[str] | None = None
    licenses: list[str] | None = None
    severity: list[Severity] | None = None
    found_after: datetime | None = None
    sort: IssueRevisionSort | None = None
    team_ids: list[str] | None = None
    page: int = Field(default=1, ge=1)
    count: int = Field(default=20, ge=1, le=1000)

    @model_validator(mode="after")
    def _validate_comparison_and_category(self) -> "IssueRevisionListInput":
        if self.scope_type == "global":
            if self.compare_to_revision is not None:
                raise ValueError("compare_to_revision must be None for global scope")
            if self.change_status is not None:
                raise ValueError("change_status must be None for global scope")
        elif (self.compare_to_revision is not None) != (self.change_status is not None):
            raise ValueError(
                "compare_to_revision and change_status must be set together or both unset"
            )

        if self.category != "vulnerability" and self.severity is not None:
            raise ValueError("severity filter is only allowed for vulnerability category")

        return self


class IssueCompareSummaryInput(BaseModel):
    """Input model for fossa_compare_issue_summaries.

    This endpoint has no global scope: comparison only means something between
    two revisions of one project.
    """

    model_config = ConfigDict(extra="forbid")

    category: IssueCategory
    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)
    compare_to_revision: str = Field(min_length=1)
    change_status: ChangeStatus | None = None
    search: str | None = None
    depths: list[IssueDepth] | None = None
    issue_types: list[str] | None = None
    package_managers: list[str] | None = None
    cwes: list[str] | None = None
    project_labels: list[str] | None = None
    severity: list[Severity] | None = None

    @model_validator(mode="after")
    def _validate_category_filters(self) -> "IssueCompareSummaryInput":
        if self.category != "vulnerability":
            if self.severity is not None:
                raise ValueError("severity filter is only allowed for vulnerability category")
            if self.cwes is not None:
                raise ValueError("cwes filter is only allowed for vulnerability category")
        elif self.issue_types is not None:
            raise ValueError("issue_types is not allowed for vulnerability category")
        return self


class IssueAffectedProjectsInput(IssueScopeInput):
    """Input model for fossa_get_issue_affected_projects."""

    issue_id: int = Field(ge=1)
    category: IssueCategory


class IssueCsvExportInput(BaseModel):
    """Input model for fossa_export_global_issues_csv."""

    model_config = ConfigDict(extra="forbid")

    email: bool = True
    team_ids: list[str] | None = None


class IssueExceptionReadInput(BaseModel):
    """Input model for fossa_get_issue_exceptions.

    One exception is fetched by id; a list is fetched by category. The two are
    the same tool because they return the same record shape, but their
    arguments do not mix.
    """

    model_config = ConfigDict(extra="forbid")

    exception_id: int | None = Field(default=None, ge=1)
    category: IssueCategory | None = None
    project_id: str | None = None
    release_group_id: int | None = Field(default=None, ge=1)
    search: str | None = None
    sort_by: ExceptionSortBy | None = None
    order_by: SortOrder | None = None
    page: int = Field(default=1, ge=1)
    count: int = Field(default=20, ge=1, le=1000)

    @model_validator(mode="after")
    def _validate_mode(self) -> "IssueExceptionReadInput":
        if self.exception_id is None:
            if self.category is None:
                raise ValueError("category is required when listing issue exceptions")
            return self

        conflicting = {
            "category": self.category,
            "project_id": self.project_id,
            "release_group_id": self.release_group_id,
            "search": self.search,
            "sort_by": self.sort_by,
            "order_by": self.order_by,
        }
        for name, value in conflicting.items():
            if value is not None:
                raise ValueError(f"{name} must be None when exception_id is given")
        return self


class IssueUpdateInput(BaseModel):
    """Input model for fossa_update_issues.

    `PUT /v2/issues` applies one action either to a list of issue ids or to
    everything matching the current filters. The unfiltered form would act on
    every issue in the organization for the given category, so at least one of
    `issue_ids`, a project scope, or a filter must be present.

    The endpoint's fifth body variant, `export`, creates Jira or custom tracker
    tickets. It is not exposed: it needs a tracker configuration surface that
    does not belong in this domain, and a mis-selected bulk export files tickets
    in someone else's system.
    """

    model_config = ConfigDict(extra="forbid")

    action: IssueUpdateAction
    category: IssueCategory
    issue_ids: list[int] | None = None
    status: IssueStatus = "active"
    scope_type: ScopeType = "global"
    project_locator: str | None = None
    revision_locator: str | None = None
    search: str | None = None
    depths: list[IssueDepth] | None = None
    issue_types: list[str] | None = None
    package_managers: list[str] | None = None
    cwes: list[str] | None = None
    project_labels: list[str] | None = None
    licenses: list[str] | None = None
    severity: list[Severity] | None = None
    severity_source: list[SeveritySource] | None = None
    revision_ids: list[str] | None = None
    found_after: datetime | None = None
    notes: str | None = None
    reason: IgnoreReason | None = None
    package_scope: PackageScope | None = None
    ignore_scope: IgnoreScope | None = None
    expires_after: date | None = None
    license_id: str | None = None

    @property
    def targets_a_filter(self) -> bool:
        """True when the action applies to a filter rather than named issues."""
        return not self.issue_ids

    @model_validator(mode="after")
    def _validate_target_and_action(self) -> "IssueUpdateInput":
        if self.scope_type == "global":
            if self.project_locator is not None:
                raise ValueError("project_locator must be None for global scope")
            if self.revision_locator is not None:
                raise ValueError("revision_locator must be None for global scope")
        else:
            if self.project_locator is None:
                raise ValueError("project_locator is required for project scope")
            if self.revision_locator is None:
                raise ValueError("revision_locator is required for project scope")

        if self.issue_ids is not None and not self.issue_ids:
            raise ValueError("issue_ids must name at least one issue when given")

        has_filter = any(getattr(self, name) is not None for name in _UPDATE_FILTER_FIELDS)
        if self.issue_ids is None and self.scope_type == "global" and not has_filter:
            raise ValueError(
                "refusing to act on every issue in the organization: pass issue_ids, "
                "a project scope, or at least one filter"
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

        exception_only = {
            "package_scope": self.package_scope,
            "ignore_scope": self.ignore_scope,
            "expires_after": self.expires_after,
            "license_id": self.license_id,
        }
        if self.action != "issueException":
            for name, value in exception_only.items():
                if value is not None:
                    raise ValueError(f"{name} is only allowed for the issueException action")

        if self.action in ("unignore", "unlink"):
            if self.notes is not None:
                raise ValueError(f"notes is not allowed for the {self.action} action")
            if self.reason is not None:
                raise ValueError(f"reason is not allowed for the {self.action} action")

        return self


class IssueExceptionExtendInput(BaseModel):
    """Input model for fossa_extend_issue_exception.

    `expires_after` is deliberately required with no default: `None` is a
    meaningful value that clears the expiry so the exception never expires, and
    an omitted argument must not silently mean that.
    """

    model_config = ConfigDict(extra="forbid")

    exception_id: int = Field(ge=1)
    expires_after: date | None


class IssueExceptionDeleteInput(BaseModel):
    """Input model for fossa_delete_issue_exceptions.

    Three mutually exclusive targets: one exception by id, a list of ids, or
    every exception matching a filter. The filter form must name at least one
    filter, so there is no way to ask for "all exceptions in the organization".
    """

    model_config = ConfigDict(extra="forbid")

    exception_id: int | None = Field(default=None, ge=1)
    exception_ids: list[int] | None = None
    category: ExceptionDeleteCategory | None = None
    project_id: str | None = None
    release_group_id: int | None = Field(default=None, ge=1)
    policy_id: int | None = Field(default=None, ge=1)

    @property
    def has_filters(self) -> bool:
        """True when the delete targets a filter rather than named ids."""
        return any(getattr(self, name) is not None for name in _EXCEPTION_FILTER_FIELDS)

    @model_validator(mode="after")
    def _validate_target(self) -> "IssueExceptionDeleteInput":
        modes = [self.exception_id is not None, self.exception_ids is not None, self.has_filters]
        if sum(modes) != 1:
            raise ValueError(
                "pass exactly one of exception_id, exception_ids, or a filter "
                "(category, project_id, release_group_id, policy_id)"
            )
        if self.exception_ids is not None and not self.exception_ids:
            raise ValueError("exception_ids must name at least one exception when given")
        return self


class IssueDisputeInput(BaseModel):
    """Input model for fossa_create_issue_dispute."""

    model_config = ConfigDict(extra="forbid")

    issue_id: int = Field(ge=1)
    reason: DisputeReason
    comment: str | None = None


class IssueOverviewInput(BaseModel):
    """Input model for fossa_get_issue_overview and fossa_export_issue_overview."""

    model_config = ConfigDict(extra="forbid")

    start: datetime | None = None
    end: datetime | None = None
    category: IssueCategory | None = None
    project_id: str | None = None
    label_ids: list[int] | None = None
    team_ids: list[str] | None = None

    @model_validator(mode="after")
    def _validate_window(self) -> "IssueOverviewInput":
        if self.start is not None and self.end is not None and self.start > self.end:
            raise ValueError("start must not be after end")
        if self.label_ids is not None and any(label < 0 for label in self.label_ids):
            raise ValueError("label_ids must be non-negative")
        return self


class IssueFilterReadInput(BaseModel):
    """Input model for fossa_get_issue_filters."""

    model_config = ConfigDict(extra="forbid")

    category: IssueCategory | None = None
    filter_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _validate_mode(self) -> "IssueFilterReadInput":
        if self.filter_id is None:
            if self.category is None:
                raise ValueError("category is required when listing saved issue filters")
        elif self.category is not None:
            raise ValueError("category must be None when filter_id is given")
        return self


class IssueFilterSaveInput(BaseModel):
    """Input model for fossa_save_issue_filter.

    `criteria` is passed through as-is. The endpoint's schema is a three-way
    `oneOf` keyed on issue category with around fifteen optional members each,
    and modeling it here would only add a second place for it to drift.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    criteria: dict[str, Any]
    filter_id: int | None = Field(default=None, ge=1)
    category: IssueCategory | None = None
    sort: IssueFilterSort | None = None
    group: IssueFilterGroup | None = None

    @model_validator(mode="after")
    def _validate_mode(self) -> "IssueFilterSaveInput":
        if self.filter_id is None:
            if self.category is None:
                raise ValueError("category is required when creating a saved issue filter")
        elif self.category is not None:
            raise ValueError(
                "category cannot be changed on an existing filter; omit it when filter_id is given"
            )
        return self


class IssueFilterDeleteInput(BaseModel):
    """Input model for fossa_delete_issue_filter."""

    model_config = ConfigDict(extra="forbid")

    filter_id: int = Field(ge=1)
