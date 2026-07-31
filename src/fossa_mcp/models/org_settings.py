"""Input models for the organization settings and organization limits tools.

Organization Settings is 57 FOSSA operations across 22 near-identical
`get`/`put`/`patch` triples that differ only by the section name in the path.
Exposed one-to-one that would be 57 tools for one page of the FOSSA web app, so
the domain is grouped: a section name selects the endpoint, and an action
selects the verb (see API_PARITY_PLAN.md, "Tool shape: tiered hybrid", and
DECISIONS.md §7).

Grouping only stays safe if the section is closed. Every `Literal` and every
table below is derived mechanically from `spec/fossa-openapi.json` by
enumerating the `/organizations/{id}` paths and reading each request body, so an
unknown section is a schema error at the MCP client rather than a 404 from
FOSSA. That closure is the line between a grouped tool and the generic
`fossa_request` proxy DECISIONS.md §7 rules out.

The tables live here, beside the `Literal`s they must agree with, so the two
cannot drift: `tests/test_org_settings_tools.py` asserts every `Literal` member
has a table entry and vice versa.
"""

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- section names -----------------------------------------------------------

# The 22 readable sections. Each name is its path below `/settings/` with `/`
# replaced by `-`, so the name and the endpoint are mechanically related.
OrgSettingsSection = Literal[
    "authentication",
    "general",
    "integrations-custom-license-scans",
    "integrations-slack",
    "languages-bower",
    "languages-gem",
    "languages-git",
    "languages-mvn",
    "languages-npm",
    "languages-nuget",
    "languages-pip",
    "languages-pod",
    "projects-github-status-checks",
    "projects-hidden-snippet-urls",
    "projects-issues-container",
    "projects-issues-licensing",
    "projects-issues-quality",
    "projects-issues-security",
    "projects-notifications",
    "projects-privacy",
    "projects-quick-import-scan-methods",
    "projects-update-hooks",
]

# The 23 writable sections: the 21 readable sections that also accept a `PUT`
# (`integrations-slack` is read-only in the API), plus two org-level
# configuration endpoints that sit outside `/settings/` but belong to the same
# page of the product — `saml` and `sbom-report-defaults`. `saml` has no `GET`,
# so it is writable-only; the SAML state it produces is reported by the
# `authentication` section instead.
OrgSettingsWritableSection = Literal[
    "authentication",
    "general",
    "integrations-custom-license-scans",
    "languages-bower",
    "languages-gem",
    "languages-git",
    "languages-mvn",
    "languages-npm",
    "languages-nuget",
    "languages-pip",
    "languages-pod",
    "projects-github-status-checks",
    "projects-hidden-snippet-urls",
    "projects-issues-container",
    "projects-issues-licensing",
    "projects-issues-quality",
    "projects-issues-security",
    "projects-notifications",
    "projects-privacy",
    "projects-quick-import-scan-methods",
    "projects-update-hooks",
    "saml",
    "sbom-report-defaults",
]

# "replace" is the section's `PUT`: it writes the organization-level default.
# "propagate" is the section's `PATCH`: it pushes named organization defaults
# down onto every existing project, overwriting per-project values.
OrgSettingsAction = Literal["replace", "propagate"]

# The only two organization-level configuration deletes in the API.
OrgSettingsDeleteTarget = Literal["saml", "logo"]

OrgLimit = Literal["contributors", "release-groups"]


# --- spec-derived tables -----------------------------------------------------

# Path suffixes below `/organizations/{id}`.
ORG_SETTINGS_READ_PATHS: dict[str, str] = {
    "authentication": "/settings/authentication",
    "general": "/settings/general",
    "integrations-custom-license-scans": "/settings/integrations/custom-license-scans",
    "integrations-slack": "/settings/integrations/slack",
    "languages-bower": "/settings/languages/bower",
    "languages-gem": "/settings/languages/gem",
    "languages-git": "/settings/languages/git",
    "languages-mvn": "/settings/languages/mvn",
    "languages-npm": "/settings/languages/npm",
    "languages-nuget": "/settings/languages/nuget",
    "languages-pip": "/settings/languages/pip",
    "languages-pod": "/settings/languages/pod",
    "projects-github-status-checks": "/settings/projects/github-status-checks",
    "projects-hidden-snippet-urls": "/settings/projects/hidden-snippet-urls",
    "projects-issues-container": "/settings/projects/issues/container",
    "projects-issues-licensing": "/settings/projects/issues/licensing",
    "projects-issues-quality": "/settings/projects/issues/quality",
    "projects-issues-security": "/settings/projects/issues/security",
    "projects-notifications": "/settings/projects/notifications",
    "projects-privacy": "/settings/projects/privacy",
    "projects-quick-import-scan-methods": "/settings/projects/quick-import-scan-methods",
    "projects-update-hooks": "/settings/projects/update-hooks",
}

ORG_LIMIT_PATHS: dict[str, str] = {
    "contributors": "/limits/contributors",
    "release-groups": "/limits/release-groups",
}

ORG_SETTINGS_DELETE_PATHS: dict[str, str] = {
    "saml": "/saml",
    "logo": "/logo",
}

# How a section's `PUT` body is shaped. Two sections take a bare JSON array
# rather than an object, which is why the update tool has both a `values` and an
# `items` parameter instead of one.
OrgSettingsBodyKind = Literal["object", "string-array", "object-array"]


@dataclass(frozen=True)
class WritableSection:
    """One writable section's `PUT` contract, as the vendored spec declares it."""

    path: str
    body: OrgSettingsBodyKind
    keys: tuple[str, ...]
    """Accepted body keys. For `object-array`, the keys of each array element."""
    required: tuple[str, ...] = ()
    """Keys the spec marks required. Empty for both array-bodied sections."""


ORG_SETTINGS_WRITE_SECTIONS: dict[str, WritableSection] = {
    "authentication": WritableSection(
        path="/settings/authentication",
        body="object",
        keys=("subdomain", "disableInvite"),
    ),
    "general": WritableSection(
        path="/settings/general",
        body="object",
        keys=(
            "labels",
            "packageLabels",
            "title",
            "email",
            "defaultRoleId",
            "dependencySignatures",
            "disableNonCustomTeamUserRoles",
            "snippetSourceCodeRetentionDays",
            "licenseConcludedEnabled",
        ),
    ),
    "integrations-custom-license-scans": WritableSection(
        path="/settings/integrations/custom-license-scans",
        body="object-array",
        keys=("name", "matchCriteria", "id"),
    ),
    "languages-bower": WritableSection(
        path="/settings/languages/bower",
        body="object",
        keys=("registries", "useArtifactory"),
    ),
    "languages-gem": WritableSection(
        path="/settings/languages/gem",
        body="object",
        keys=("sources",),
    ),
    "languages-git": WritableSection(
        path="/settings/languages/git",
        body="object",
        keys=("authOptions",),
    ),
    "languages-mvn": WritableSection(
        path="/settings/languages/mvn",
        body="object",
        keys=("repositories", "servers"),
    ),
    "languages-npm": WritableSection(
        path="/settings/languages/npm",
        body="object",
        keys=("registries",),
    ),
    "languages-nuget": WritableSection(
        path="/settings/languages/nuget",
        body="object",
        keys=("sources",),
    ),
    "languages-pip": WritableSection(
        path="/settings/languages/pip",
        body="object",
        keys=("repositories",),
    ),
    "languages-pod": WritableSection(
        path="/settings/languages/pod",
        body="string-array",
        keys=(),
    ),
    "projects-github-status-checks": WritableSection(
        path="/settings/projects/github-status-checks",
        body="object",
        keys=(
            "projectDefaultAutomatedIntegrationhookTimeout",
            "projectDefaultProvidedIntegrationhookTimeout",
            "projectDefaultIntegrationhookFailState",
        ),
    ),
    "projects-hidden-snippet-urls": WritableSection(
        path="/settings/projects/hidden-snippet-urls",
        body="object",
        keys=("projectDefaultHiddenSnippetUrls",),
        required=("projectDefaultHiddenSnippetUrls",),
    ),
    "projects-issues-container": WritableSection(
        path="/settings/projects/issues/container",
        body="object",
        keys=(
            "projectDefaultExcludeBaseLayerIssuesLicensing",
            "projectDefaultExcludeBaseLayerIssuesSecurity",
            "projectDefaultExcludeBaseLayerIssuesQuality",
        ),
    ),
    "projects-issues-licensing": WritableSection(
        path="/settings/projects/issues/licensing",
        body="object",
        keys=(
            "defaultPolicyId",
            "projectDefaultLicensingIssueScanningEnabled",
            "projectDefaultLicensingStatusCheckEnabled",
            "projectDefaultStatusCheckFilterLicensing",
            "projectDefaultSnippetLicensingIssueScanningEnabled",
            "projectDefaultVendoredLicensingIssueScanningEnabled",
        ),
    ),
    "projects-issues-quality": WritableSection(
        path="/settings/projects/issues/quality",
        body="object",
        keys=(
            "defaultQualityPolicyId",
            "projectDefaultQualityIssueScanningEnabled",
            "projectDefaultQualityStatusCheckEnabled",
            "projectDefaultStatusCheckFilterQuality",
            "projectDefaultVendoredQualityIssueScanningEnabled",
        ),
    ),
    "projects-issues-security": WritableSection(
        path="/settings/projects/issues/security",
        body="object",
        keys=(
            "defaultSecurityPolicyId",
            "projectDefaultSecurityIssueScanningEnabled",
            "projectDefaultSecurityStatusCheckEnabled",
            "projectDefaultStatusCheckFilterVulnerability",
            "projectDefaultSnippetSecurityIssueScanningEnabled",
            "projectDefaultVendoredSecurityIssueScanningEnabled",
        ),
    ),
    "projects-notifications": WritableSection(
        path="/settings/projects/notifications",
        body="object",
        keys=(
            "notificationDefaultEnabled",
            "notificationDefaultSlackScan",
            "notificationDefaultApiWebhookScan",
            "notificationDefaultEmailScanUsers",
            "notificationDefaultEmailScanUserType",
        ),
        required=(
            "notificationDefaultEnabled",
            "notificationDefaultSlackScan",
            "notificationDefaultApiWebhookScan",
            "notificationDefaultEmailScanUsers",
            "notificationDefaultEmailScanUserType",
        ),
    ),
    "projects-privacy": WritableSection(
        path="/settings/projects/privacy",
        body="object",
        keys=("defaultProjectPrivacy",),
    ),
    "projects-quick-import-scan-methods": WritableSection(
        path="/settings/projects/quick-import-scan-methods",
        body="object",
        keys=(
            "projectDefaultQuickImportVendoredDetectionEnabled",
            "projectDefaultQuickImportSnippetDetectionEnabled",
        ),
        required=(
            "projectDefaultQuickImportVendoredDetectionEnabled",
            "projectDefaultQuickImportSnippetDetectionEnabled",
        ),
    ),
    "projects-update-hooks": WritableSection(
        path="/settings/projects/update-hooks",
        body="object",
        keys=(
            "updateHookDefaultScheduledEnabled",
            "updateHookDefaultScheduledInterval",
            "updateHookDefaultScheduledIntervalLength",
            "updateHookDefaultScheduledIntervalTime",
        ),
    ),
    "saml": WritableSection(
        path="/saml",
        body="object",
        keys=(
            "entryPoint",
            "cert",
            "audience",
            "orgRoleManagement",
            "teamRoleManagement",
            "createMissingTeams",
        ),
        required=("entryPoint", "cert", "audience"),
    ),
    "sbom-report-defaults": WritableSection(
        path="/sbomReportDefaults",
        body="object",
        keys=("sbomReportAuthorName", "sbomReportAuthorEmail", "sbomReportSupplier"),
    ),
}

# The 10 sections whose `PATCH` propagates organization defaults onto existing
# projects, and the fields each one will propagate. These lists are *not* the
# section's `PUT` key list: `projects-notifications` accepts five keys on `PUT`
# but propagates only three. Enforce the propagate list, not the write list.
ORG_SETTINGS_PROPAGATE_FIELDS: dict[str, tuple[str, ...]] = {
    "projects-github-status-checks": (
        "projectDefaultAutomatedIntegrationhookTimeout",
        "projectDefaultProvidedIntegrationhookTimeout",
        "projectDefaultIntegrationhookFailState",
    ),
    "projects-hidden-snippet-urls": ("projectDefaultHiddenSnippetUrls",),
    "projects-issues-container": (
        "projectDefaultExcludeBaseLayerIssuesLicensing",
        "projectDefaultExcludeBaseLayerIssuesSecurity",
        "projectDefaultExcludeBaseLayerIssuesQuality",
    ),
    "projects-issues-licensing": (
        "defaultPolicyId",
        "projectDefaultLicensingIssueScanningEnabled",
        "projectDefaultLicensingStatusCheckEnabled",
        "projectDefaultStatusCheckFilterLicensing",
        "projectDefaultSnippetLicensingIssueScanningEnabled",
        "projectDefaultVendoredLicensingIssueScanningEnabled",
    ),
    "projects-issues-quality": (
        "defaultQualityPolicyId",
        "projectDefaultQualityIssueScanningEnabled",
        "projectDefaultQualityStatusCheckEnabled",
        "projectDefaultStatusCheckFilterQuality",
        "projectDefaultVendoredQualityIssueScanningEnabled",
    ),
    "projects-issues-security": (
        "defaultSecurityPolicyId",
        "projectDefaultSecurityIssueScanningEnabled",
        "projectDefaultSecurityStatusCheckEnabled",
        "projectDefaultStatusCheckFilterVulnerability",
        "projectDefaultSnippetSecurityIssueScanningEnabled",
        "projectDefaultVendoredSecurityIssueScanningEnabled",
    ),
    "projects-notifications": (
        "notificationDefaultEmailScanUsers",
        "notificationDefaultSlackScan",
        "notificationDefaultApiWebhookScan",
    ),
    "projects-privacy": ("defaultProjectPrivacy",),
    "projects-quick-import-scan-methods": (
        "projectDefaultQuickImportVendoredDetectionEnabled",
        "projectDefaultQuickImportSnippetDetectionEnabled",
    ),
    "projects-update-hooks": (
        "updateHookDefaultScheduledEnabled",
        "updateHookDefaultScheduledInterval",
        "updateHookDefaultScheduledIntervalLength",
        "updateHookDefaultScheduledIntervalTime",
    ),
}

# Keys in the `general` section that decide what a user may do: `defaultRoleId`
# is the role every new organization member is given, and
# `disableNonCustomTeamUserRoles` withdraws FOSSA's built-in team roles. Writing
# either is an access-control change, so it is gated at the ADMIN tier even
# though the rest of `general` (title, email, label vocabulary) is an ordinary
# WRITE. See `tools/org_settings.py`.
ORG_SETTINGS_GENERAL_ACCESS_CONTROL_KEYS: frozenset[str] = frozenset(
    {"defaultRoleId", "disableNonCustomTeamUserRoles"}
)


def _dedupe(values: list[str]) -> list[str]:
    """Drop repeats while keeping first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


# --- input models ------------------------------------------------------------


class OrgSettingsReadInput(BaseModel):
    """Input model for fossa_org_settings."""

    model_config = ConfigDict(extra="forbid")

    sections: list[OrgSettingsSection] = Field(min_length=1)

    @model_validator(mode="after")
    def _dedupe_sections(self) -> "OrgSettingsReadInput":
        # Each section is one FOSSA request, so a repeated section would buy a
        # duplicate round trip and nothing else.
        self.sections = _dedupe(list(self.sections))  # type: ignore[assignment]
        return self


class OrgLimitsReadInput(BaseModel):
    """Input model for fossa_org_limits."""

    model_config = ConfigDict(extra="forbid")

    limits: list[OrgLimit] = Field(min_length=1)

    @model_validator(mode="after")
    def _dedupe_limits(self) -> "OrgLimitsReadInput":
        self.limits = _dedupe(list(self.limits))  # type: ignore[assignment]
        return self


class OrgSettingsUpdateInput(BaseModel):
    """Input model for fossa_update_org_settings.

    The section decides which of `values` and `items` is the body, and the
    action decides whether a body is wanted at all. Everything is checked here,
    before the tool asks for a write tier, so a malformed call never reaches the
    gate and never reaches FOSSA.
    """

    model_config = ConfigDict(extra="forbid")

    section: OrgSettingsWritableSection
    action: OrgSettingsAction = "replace"
    values: dict[str, Any] | None = None
    items: list[Any] | None = None
    fields: list[str] | None = None

    @model_validator(mode="after")
    def _validate_against_section(self) -> "OrgSettingsUpdateInput":
        if self.action == "propagate":
            self._validate_propagate()
        else:
            self._validate_replace()
        return self

    def _validate_propagate(self) -> None:
        allowed = ORG_SETTINGS_PROPAGATE_FIELDS.get(self.section)
        if allowed is None:
            raise ValueError(
                f"Section {self.section!r} has no propagate action; only these sections "
                f"can push their organization default onto existing projects: "
                f"{', '.join(sorted(ORG_SETTINGS_PROPAGATE_FIELDS))}."
            )
        if self.values is not None or self.items is not None:
            raise ValueError(
                "action='propagate' names fields to push out and carries no body; "
                "set values/items with action='replace' first, then propagate."
            )
        if not self.fields:
            raise ValueError(
                f"action='propagate' requires fields. Section {self.section!r} can "
                f"propagate: {', '.join(allowed)}."
            )
        unknown = [field for field in self.fields if field not in allowed]
        if unknown:
            raise ValueError(
                f"Section {self.section!r} cannot propagate {', '.join(sorted(unknown))}. "
                f"It propagates: {', '.join(allowed)}."
            )
        self.fields = _dedupe(self.fields)

    def _validate_replace(self) -> None:
        if self.fields is not None:
            raise ValueError("fields is only meaningful with action='propagate'.")

        spec = ORG_SETTINGS_WRITE_SECTIONS[self.section]

        if spec.body == "object":
            if self.items is not None:
                raise ValueError(
                    f"Section {self.section!r} takes an object body; pass values, not items."
                )
            if self.values is None:
                raise ValueError(f"Section {self.section!r} requires values.")
            self._validate_object_values(spec)
            return

        if self.values is not None:
            raise ValueError(
                f"Section {self.section!r} takes a bare JSON array body; pass items, not values."
            )
        if self.items is None:
            raise ValueError(f"Section {self.section!r} requires items.")
        if spec.body == "string-array":
            self._validate_string_items()
        else:
            self._validate_object_items(spec)

    def _validate_object_values(self, spec: WritableSection) -> None:
        assert self.values is not None
        unknown = sorted(set(self.values) - set(spec.keys))
        if unknown:
            raise ValueError(
                f"Section {self.section!r} does not accept {', '.join(unknown)}. "
                f"It accepts: {', '.join(spec.keys)}."
            )
        missing = [key for key in spec.required if key not in self.values]
        if missing:
            # These endpoints replace the section wholesale rather than merging,
            # so a required key left out is not "unchanged" — FOSSA rejects it.
            raise ValueError(
                f"Section {self.section!r} replaces the whole section and requires "
                f"{', '.join(spec.required)}; missing: {', '.join(missing)}."
            )
        if not self.values:
            raise ValueError(f"Section {self.section!r} requires at least one value.")

    def _validate_string_items(self) -> None:
        assert self.items is not None
        if not self.items:
            raise ValueError(f"Section {self.section!r} requires at least one item.")
        bad = [item for item in self.items if not isinstance(item, str)]
        if bad:
            raise ValueError(f"Section {self.section!r} takes an array of strings.")

    def _validate_object_items(self, spec: WritableSection) -> None:
        assert self.items is not None
        if not self.items:
            raise ValueError(f"Section {self.section!r} requires at least one item.")
        for index, item in enumerate(self.items):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Section {self.section!r} takes an array of objects; item {index} is not one."
                )
            unknown = sorted(set(item) - set(spec.keys))
            if unknown:
                raise ValueError(
                    f"Section {self.section!r} item {index} does not accept "
                    f"{', '.join(unknown)}. It accepts: {', '.join(spec.keys)}."
                )


class OrgSettingsDeleteInput(BaseModel):
    """Input model for fossa_delete_org_setting."""

    model_config = ConfigDict(extra="forbid")

    target: OrgSettingsDeleteTarget
