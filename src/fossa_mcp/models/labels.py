"""Input models for the label tools.

Two unrelated things in FOSSA are called a label, and keeping them apart is the
main job of this module:

* **Organization labels** tag *projects*. They are what
  `fossa_apply_project_label` (in `tools/projects.py`) applies, and they are
  addressed by a numeric id.
* **Package labels** tag *packages* — a dependency, at a version, within a
  scope. A package label is a definition (`/package-labels`) plus zero or more
  assignments (`/package-label-assignments`) that bind it to a package.

**The blank-version rule.** `POST /package-label-assignments` documents
`packageVersion` as "the version of the package to assign labels to or blank for
all versions". An omitted or empty version is therefore not a narrower request,
it is a *wider* one — every version of that package in the scope, silently. No
model here lets a blank version through. `PackageLabelAssignInput` requires
either a non-blank `package_version` or an explicit `apply_to_all_versions=True`
and refuses both together, so the wide form is only reachable by naming it, and
a caller who forgets the version gets a validation error rather than an
organization-wide assignment. The same reasoning drives
`apply_to_all_versions` on `PackageLabelBulkAssignInput`, which maps to the
endpoint's inverted `shouldUseSpecificVersion` flag and is always sent
explicitly rather than relying on FOSSA's documented default.

The one place "every version" is expressible as data is
`PackageLabelReconcileInput.new_label_ids`, whose keys are version strings and
where the literal key `all` is what the endpoint itself defines as the
all-versions bucket. That is a named key in a map the caller wrote, not an
omission, so it is allowed.

**Scope ids.** `scope` is `org`, `project`, or `revision`. FOSSA documents
`scopeId` as "required if scope is 'project' or 'revision'" on the bulk endpoint
and leaves it merely optional on the others; the rule is applied uniformly here,
and `org` scope must not carry a `scopeId` at all. A mismatched pair is a
schema error rather than an assignment attached to the wrong thing.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Where a package label assignment applies: the whole organization, one
# project, or one revision. The Literal keeps an invented scope a client-side
# schema error instead of a 400 from FOSSA.
PackageLabelScope = Literal["org", "project", "revision"]

# The key `PUT /package-label-assignments` reserves in `newLabelIds` for
# assignments that apply to every version of the package.
ALL_VERSIONS_KEY = "all"


def _check_scope_pairing(scope: PackageLabelScope, scope_id: str | None) -> None:
    """Enforce that `scope` and `scope_id` agree.

    `org` scope addresses the whole organization and has nothing to point at, so
    a `scope_id` alongside it is a sign the caller meant `project` or `revision`
    and would otherwise have it silently ignored.
    """
    if scope == "org":
        if scope_id is not None:
            raise ValueError('scope_id must be omitted when scope is "org"')
        return
    if scope_id is None or not scope_id.strip():
        raise ValueError(f'scope_id is required when scope is "{scope}"')


def _check_label_ids(label_ids: list[int], field_name: str) -> list[int]:
    """Validate a non-empty list of positive label or assignment ids."""
    if not label_ids:
        raise ValueError(f"{field_name} must name at least one id")
    if any(value < 1 for value in label_ids):
        raise ValueError(f"{field_name} ids must be >= 1")
    return label_ids


class PackageLabelListInput(BaseModel):
    """Input model for fossa_list_package_labels.

    `GET /package-labels` declares no parameters at all; the model exists so the
    tool is constructed the same way as every other one in this module.
    """

    model_config = ConfigDict(extra="forbid")


class PackageLabelCreateInput(BaseModel):
    """Input model for fossa_create_package_labels."""

    model_config = ConfigDict(extra="forbid")

    labels: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_labels(self) -> "PackageLabelCreateInput":
        if any(not label.strip() for label in self.labels):
            raise ValueError("labels must not contain blank entries")
        return self


class PackageLabelDeleteInput(BaseModel):
    """Input model for fossa_delete_package_labels."""

    model_config = ConfigDict(extra="forbid")

    label_ids: list[int]

    @model_validator(mode="after")
    def _check_ids(self) -> "PackageLabelDeleteInput":
        _check_label_ids(self.label_ids, "label_ids")
        return self


class PackageLabelAssignmentListInput(BaseModel):
    """Input model for fossa_list_package_label_assignments.

    Every filter is optional and unfiltered means "every assignment in the
    organization", which the endpoint documents and this tool passes through —
    it is a read, so the cost of a wide answer is a large page, not a change.

    `package_version` is constrained to a non-blank string. FOSSA also accepts
    an empty value here to mean "labels that apply to all versions", but that
    spelling is one keystroke away from an unintended filter, and
    `include_package_wide_labels` reaches the same rows next to a real version.
    """

    model_config = ConfigDict(extra="forbid")

    package_id: str | None = Field(default=None, min_length=1)
    package_version: str | None = Field(default=None, min_length=1)
    scope: PackageLabelScope | None = None
    scope_id: str | None = Field(default=None, min_length=1)
    include_package_wide_labels: bool | None = None
    include_revision_scoped_labels: bool | None = None

    @model_validator(mode="after")
    def _check_filters(self) -> "PackageLabelAssignmentListInput":
        if self.package_version is not None and self.package_id is None:
            raise ValueError("package_version filters a package; supply package_id with it")
        if self.scope_id is not None and self.scope is None:
            raise ValueError("scope_id filters within a scope; supply scope with it")
        return self


class PackageLabelAssignInput(BaseModel):
    """Input model for fossa_assign_package_labels.

    Additive: it creates assignments and never removes one. See the module
    docstring for why `package_version` and `apply_to_all_versions` are
    mutually exclusive and one of them is mandatory.
    """

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(min_length=1)
    scope: PackageLabelScope
    label_ids: list[int]
    package_version: str | None = Field(default=None, min_length=1)
    apply_to_all_versions: bool = False
    scope_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _check_target(self) -> "PackageLabelAssignInput":
        _check_label_ids(self.label_ids, "label_ids")
        _check_scope_pairing(self.scope, self.scope_id)
        if self.apply_to_all_versions and self.package_version is not None:
            raise ValueError(
                "package_version and apply_to_all_versions are mutually exclusive; "
                "name one version or ask for all of them"
            )
        if not self.apply_to_all_versions and self.package_version is None:
            raise ValueError(
                "package_version is required; pass apply_to_all_versions=true to label "
                "every version of the package instead"
            )
        return self


class PackageLabelBulkAssignInput(BaseModel):
    """Input model for fossa_bulk_assign_package_label.

    The target set is an explicit list of revision locators — the endpoint
    exposes no filter mode — so this stays additive and bounded no matter how
    long the list is. Each locator must carry its version (`npm+lodash$4.17.21`),
    which FOSSA requires and which also means the caller cannot arrive at "every
    version" by leaving one off: that widening is only reachable through
    `apply_to_all_versions`.
    """

    model_config = ConfigDict(extra="forbid")

    label_id: int = Field(ge=1)
    package_locators: list[str]
    scope: PackageLabelScope
    scope_id: str | None = Field(default=None, min_length=1)
    apply_to_all_versions: bool = False

    @model_validator(mode="after")
    def _check_locators(self) -> "PackageLabelBulkAssignInput":
        if not self.package_locators:
            raise ValueError("package_locators must name at least one package")
        for locator in self.package_locators:
            if not locator.strip():
                raise ValueError("package_locators must not contain blank entries")
            if locator.strip().lower() == "all":
                raise ValueError(
                    'package_locators must be explicit revision locators; "all" is not accepted'
                )
            if "$" not in locator:
                raise ValueError(
                    f"package_locators must include the version, as in 'npm+lodash$4.17.21'; "
                    f"got {locator!r}"
                )
        _check_scope_pairing(self.scope, self.scope_id)
        return self


class PackageLabelReconcileInput(BaseModel):
    """Input model for fossa_set_package_label_assignments.

    `new_label_ids` is a desired end state, not an addition: FOSSA removes every
    existing assignment for the package at this scope that the map does not
    mention. An empty list for a version therefore clears that version, and a
    version left out of the map entirely is cleared too — which is why the tool
    is gated at the destructive tier despite being a `PUT`.

    Keys are version strings, or the literal `all` for the bucket that applies
    to every version.
    """

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(min_length=1)
    scope: PackageLabelScope
    new_label_ids: dict[str, list[int]]
    scope_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _check_map(self) -> "PackageLabelReconcileInput":
        if not self.new_label_ids:
            raise ValueError(
                "new_label_ids must name at least one version; an empty map would be read as "
                "a request to remove every assignment, which is not expressible here"
            )
        for version, ids in self.new_label_ids.items():
            if not version.strip():
                raise ValueError(
                    f'new_label_ids keys must be a package version or "{ALL_VERSIONS_KEY}"; '
                    "a blank key is not accepted"
                )
            # An empty list is meaningful: it clears that version's labels.
            if any(value < 1 for value in ids):
                raise ValueError(f"new_label_ids[{version!r}] must contain label ids >= 1")
        _check_scope_pairing(self.scope, self.scope_id)
        return self


class PackageLabelUnassignInput(BaseModel):
    """Input model for fossa_unassign_package_labels.

    Assignments are addressed by their own numeric ids, which come from
    `fossa_list_package_label_assignments`. There is no filter form of this
    endpoint, so the target set is always exactly what the caller listed.
    """

    model_config = ConfigDict(extra="forbid")

    assignment_ids: list[int]

    @model_validator(mode="after")
    def _check_ids(self) -> "PackageLabelUnassignInput":
        _check_label_ids(self.assignment_ids, "assignment_ids")
        return self


class OrganizationLabelReadInput(BaseModel):
    """Input model for fossa_list_organization_labels.

    With `label_id` the tool reads one label and its project list; without it,
    every label in the organization.
    """

    model_config = ConfigDict(extra="forbid")

    label_id: int | None = Field(default=None, ge=1)


class OrganizationLabelCreateInput(BaseModel):
    """Input model for fossa_create_organization_label.

    The spec declares no required properties on this body, but a label with no
    text is not a label, so `label` is required here.
    """

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_label(self) -> "OrganizationLabelCreateInput":
        if not self.label.strip():
            raise ValueError("label must not be blank")
        return self


class OrganizationLabelDeleteInput(BaseModel):
    """Input model for fossa_delete_organization_label."""

    model_config = ConfigDict(extra="forbid")

    label_id: int = Field(ge=1)
