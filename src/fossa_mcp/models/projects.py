"""Input models for the project tools.

Each model is constructed from a tool's flat parameters before any request is
built, so validation failures cost nothing and never reach FOSSA.

`ProjectUpdateInput` carries serialization aliases for the FOSSA field names it
maps to (`security_policy_id` -> `securityPolicyId`). The payload is produced by
`to_payload()`, which dumps by alias and drops every unset field, because
`PUT /projects/{locator}` merges what it is sent: a key present with a `null`
value clears that setting, so a field the caller did not name must not appear in
the body at all.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import IssueStatus, RefType

# `format` selects between the two documented export paths rather than a query
# parameter; see `export_project_issues`.
ProjectExportFormat = Literal["json", "csv"]

ProjectAssociationSection = Literal["labels", "release_groups", "last_published"]


def _check_locators(locators: list[str], field_name: str) -> list[str]:
    """Validate an explicit list of project locators for a bulk operation.

    Rejects `"all"`, which the bulk endpoints accept as "every project matching
    the filters". None of these tools expose that mode, so a caller who passes
    the literal string is told rather than silently having it treated as an
    ordinary locator.
    """
    if not locators:
        raise ValueError(f"{field_name} must name at least one project")
    if any(not locator.strip() for locator in locators):
        raise ValueError(f"{field_name} must not contain blank entries")
    if any(locator.strip().lower() == "all" for locator in locators):
        raise ValueError(
            f'{field_name} must be explicit project locators; the wildcard "all" is not accepted'
        )
    return locators


class ProjectUpdateInput(BaseModel):
    """Input model for fossa_update_project.

    A deliberate subset of the 53 fields `PUT /projects/{locator}` accepts. The
    omitted ones are the nested configuration blocks (Jira custom fields,
    notification routing, BOM column settings, saved issue filters) and the
    fields FOSSA populates itself (`invalidCredential`, `bom_public_id`).
    """

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)

    # Metadata
    title: str | None = Field(default=None, min_length=1)
    description: str | None = None
    project_url: str | None = Field(default=None, serialization_alias="url")
    notes: str | None = None
    public: bool | None = None
    default_branch: str | None = Field(default=None, min_length=1)
    tracking_branches: list[str] | None = None
    hidden_branches: list[str] | None = None

    # Policy assignment
    policy_id: int | None = Field(default=None, ge=1, serialization_alias="policyId")
    security_policy_id: int | None = Field(
        default=None, ge=1, serialization_alias="securityPolicyId"
    )
    quality_policy_id: int | None = Field(default=None, ge=1, serialization_alias="qualityPolicyId")
    sbom_policy_id: int | None = Field(default=None, ge=1, serialization_alias="sbomPolicyId")
    policies_approve_multilicense: bool | None = None

    # Scanning
    licensing_issue_scanning_enabled: bool | None = Field(
        default=None, serialization_alias="licensingIssueScanningEnabled"
    )
    security_issue_scanning_enabled: bool | None = Field(
        default=None, serialization_alias="securityIssueScanningEnabled"
    )
    quality_issue_scanning_enabled: bool | None = Field(
        default=None, serialization_alias="qualityIssueScanningEnabled"
    )
    sbom_analysis_enabled: bool | None = Field(
        default=None, serialization_alias="sbomAnalysisEnabled"
    )

    # CI status checks
    licensing_status_check_enabled: bool | None = Field(
        default=None, serialization_alias="licensingStatusCheckEnabled"
    )
    security_status_check_enabled: bool | None = Field(
        default=None, serialization_alias="securityStatusCheckEnabled"
    )
    quality_status_check_enabled: bool | None = Field(
        default=None, serialization_alias="qualityStatusCheckEnabled"
    )

    # Reporting and analysis scope
    label_ids: list[int] | None = Field(default=None, serialization_alias="labels")
    transitive_excludes: list[str] | None = None
    report_custom_text: str | None = Field(default=None, serialization_alias="reportCustomText")

    @model_validator(mode="after")
    def _validate(self) -> "ProjectUpdateInput":
        if not self.to_payload():
            raise ValueError("Name at least one project field to update")

        for name in ("tracking_branches", "hidden_branches"):
            branches = getattr(self, name)
            if branches is not None and any(not branch.strip() for branch in branches):
                raise ValueError(f"{name} must not contain blank entries")

        if self.tracking_branches is not None and self.hidden_branches is not None:
            overlap = sorted(set(self.tracking_branches) & set(self.hidden_branches))
            if overlap:
                # FOSSA resolves the conflict silently by moving the branch out
                # of whichever list it was already in, so the result would not
                # match either list the caller passed.
                raise ValueError(
                    "tracking_branches and hidden_branches are mutually exclusive; "
                    f"remove {', '.join(overlap)} from one of them"
                )

        if self.label_ids is not None and any(label_id < 1 for label_id in self.label_ids):
            raise ValueError("label_ids must be positive label ids")

        if self.transitive_excludes is not None and any(
            not locator.strip() for locator in self.transitive_excludes
        ):
            raise ValueError("transitive_excludes must not contain blank entries")

        return self

    def to_payload(self) -> dict[str, Any]:
        """Return the request body: FOSSA field names, unset fields omitted."""
        return self.model_dump(by_alias=True, exclude_none=True, exclude={"project_locator"})


class ProjectDeleteInput(BaseModel):
    """Input model for fossa_delete_project."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)

    @model_validator(mode="after")
    def _validate(self) -> "ProjectDeleteInput":
        if not self.project_locator.strip():
            raise ValueError("project_locator must not be blank")
        return self


class ProjectBulkDeleteInput(BaseModel):
    """Input model for fossa_delete_projects."""

    model_config = ConfigDict(extra="forbid")

    project_locators: list[str]

    @model_validator(mode="after")
    def _validate(self) -> "ProjectBulkDeleteInput":
        _check_locators(self.project_locators, "project_locators")
        return self


class ProjectLabelApplyInput(BaseModel):
    """Input model for fossa_apply_project_label."""

    model_config = ConfigDict(extra="forbid")

    label_id: int = Field(ge=1)
    project_locators: list[str]

    @model_validator(mode="after")
    def _validate(self) -> "ProjectLabelApplyInput":
        _check_locators(self.project_locators, "project_locators")
        return self


class ProjectAssociationsInput(BaseModel):
    """Input model for fossa_get_project_associations."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    sections: list[ProjectAssociationSection] | None = None

    @model_validator(mode="after")
    def _validate(self) -> "ProjectAssociationsInput":
        if self.sections is not None and not self.sections:
            raise ValueError("sections must name at least one section, or be omitted for all")
        return self

    def requested_sections(self) -> list[ProjectAssociationSection]:
        """Return the sections to fetch, deduplicated, in a stable order."""
        requested = self.sections or ["labels", "release_groups", "last_published"]
        seen: list[ProjectAssociationSection] = []
        for section in requested:
            if section not in seen:
                seen.append(section)
        return seen


class ProjectIssueExportInput(BaseModel):
    """Input model for fossa_export_project_issues."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    format: ProjectExportFormat = "json"
    revision_id: str | None = None
    status: IssueStatus | None = None
    ref: str | None = None
    ref_type: RefType | None = None

    @model_validator(mode="after")
    def _validate(self) -> "ProjectIssueExportInput":
        if self.ref_type is not None and self.ref is None:
            raise ValueError("ref_type only applies when ref is given")
        return self


class ProjectAttributionSlugInput(BaseModel):
    """Input model for the attribution slug tools."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
