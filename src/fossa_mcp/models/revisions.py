"""Input models for the revision tools.

Every model here takes the revision in two parts — `project_locator` plus
`revision_locator` — because FOSSA's revision paths want the joined
`project$revision` form and callers routinely hold only the bare revision id.
`query.split_revision_locator` does the joining, and accepts either form for
`revision_locator`, so a caller that already has the full locator can pass it
unchanged.

The attribution endpoints share one option set across four different paths
(render, JSON, email, public link), so the shared flags live in a private base
class and each endpoint's model adds only what its own signature declares.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Every format FOSSA can generate. Used where the report is delivered somewhere
# else (emailed, or uploaded behind a public link) and never passes through this
# process.
AttributionFormat = Literal[
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

# The same list without PDF. A tool that returns the report body to the model
# can only return text, and a PDF decoded as text is noise.
AttributionRenderFormat = Literal[
    "HTML",
    "MD",
    "CSV",
    "TXT",
    "SPDX",
    "SPDX_JSON",
    "CYCLONEDX_JSON",
    "CYCLONEDX_XML",
]

AttributionApiVersion = Literal["v1", "v2"]
AttributionRenderVariant = Literal["stream", "preview", "full"]
RemediationFormat = Literal["JSON", "HTML"]
SbomPart = Literal["analysis", "original"]
DependencyTransport = Literal["auto", "get", "post"]

# Model field -> FOSSA query parameter, in the order the spec lists them. The
# tool module builds query strings from this, and the "full" report variant
# checks it to reject options the endpoint does not accept.
REPORT_OPTION_QUERY_NAMES: tuple[tuple[str, str], ...] = (
    ("include_deep_dependencies", "includeDeepDependencies"),
    ("include_direct_dependencies", "includeDirectDependencies"),
    ("include_license_list", "includeLicenseList"),
    ("include_license_scan", "includeLicenseScan"),
    ("include_project_license", "includeProjectLicense"),
    ("include_copyright_list", "includeCopyrightList"),
    ("include_file_matches", "includeFileMatches"),
    ("include_open_vulnerabilities", "includeOpenVulnerabilities"),
    ("include_closed_vulnerabilities", "includeClosedVulnerabilities"),
    ("include_dependency_summary", "includeDependencySummary"),
    ("include_license_headers", "includeLicenseHeaders"),
    ("include_package_labels", "includePackageLabels"),
)

ATTRIBUTION_JSON_QUERY_NAMES: tuple[tuple[str, str], ...] = (
    ("preview", "preview"),
    ("include_deep_dependencies", "includeDeepDependencies"),
    ("include_hash_and_version_data", "includeHashAndVersionData"),
    ("include_copyright_list", "includeCopyrightList"),
    ("include_file_matches", "includeFileMatches"),
    ("include_open_vulnerabilities", "includeOpenVulnerabilities"),
    ("include_closed_vulnerabilities", "includeClosedVulnerabilities"),
    ("include_notice_files", "includeNoticeFiles"),
    ("include_package_labels", "includePackageLabels"),
)

_REPORT_OPTION_FIELDS = tuple(name for name, _ in REPORT_OPTION_QUERY_NAMES)


class _RevisionInput(BaseModel):
    """Locator fields shared by every revision tool."""

    model_config = ConfigDict(extra="forbid")

    project_locator: str = Field(min_length=1)
    revision_locator: str = Field(min_length=1)


class _ExcludeFieldsInput(_RevisionInput):
    """Adds the attribution endpoints' `excludeFields[packageLabels]` filter."""

    exclude_package_labels: list[str] | None = None

    @model_validator(mode="after")
    def _validate_exclude_package_labels(self) -> "_ExcludeFieldsInput":
        if self.exclude_package_labels is None:
            return self
        if not self.exclude_package_labels:
            raise ValueError("exclude_package_labels must name at least one label when provided")
        if any(not label.strip() for label in self.exclude_package_labels):
            raise ValueError("exclude_package_labels must not contain blank entries")
        return self


class _ReportOptions(_ExcludeFieldsInput):
    """The twelve content flags every attribution report path accepts.

    FOSSA defaults all of them to false, which produces an empty report. The
    defaults here turn on the sections that make a report worth reading; every
    flag is always sent explicitly, so nothing depends on the server default.
    """

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


class RevisionScansInput(_RevisionInput):
    """Input model for fossa_list_revision_scans."""

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=50)


class RevisionNoticeFilesInput(_RevisionInput):
    """Input model for fossa_get_revision_notice_files."""

    include_contents: bool = True


class RevisionSbomInput(_RevisionInput):
    """Input model for fossa_get_revision_sbom."""

    part: SbomPart = "analysis"


class RemediationGuidanceInput(_RevisionInput):
    """Input model for fossa_get_revision_remediation_guidance."""

    format: RemediationFormat = "JSON"
    exclude_quick_wins: bool = False
    exclude_high_priority: bool = False
    exclude_low_priority: bool = False
    exclude_outdated_dependencies: bool = False
    include_transitive_vulnerabilities: bool = False
    deduplicate_outdated_dependencies: bool = False
    include_malware: bool = False


class RevisionAttributionJsonInput(_ExcludeFieldsInput):
    """Input model for fossa_get_revision_attribution_json."""

    api_version: AttributionApiVersion = "v2"
    preview: bool = False
    include_deep_dependencies: bool = True
    include_hash_and_version_data: bool = False
    include_copyright_list: bool = False
    include_file_matches: bool = False
    include_open_vulnerabilities: bool = False
    include_closed_vulnerabilities: bool = False
    include_notice_files: bool = False
    include_package_labels: bool = False


class RevisionAttributionRenderInput(_ReportOptions):
    """Input model for fossa_render_revision_attribution."""

    variant: AttributionRenderVariant = "stream"
    format: AttributionRenderFormat = "MD"
    include_hash_and_version_data: bool = False

    @model_validator(mode="after")
    def _validate_full_variant(self) -> "RevisionAttributionRenderInput":
        # `/attribution/full/{format}` takes no query parameters at all: it
        # enables every option server-side. Silently dropping the caller's
        # options would report a filtered report that was never filtered.
        if self.variant != "full":
            return self

        fields = type(self).model_fields
        overridden = [
            name
            for name in (*_REPORT_OPTION_FIELDS, "include_hash_and_version_data")
            if getattr(self, name) != fields[name].default
        ]
        if self.exclude_package_labels is not None:
            overridden.append("exclude_package_labels")
        if overridden:
            raise ValueError(
                "variant='full' enables every report option server-side and accepts no "
                f"options; leave {sorted(overridden)} at the default"
            )
        return self


class RevisionAttributionEmailInput(_ReportOptions):
    """Input model for fossa_email_revision_attribution."""

    api_version: AttributionApiVersion = "v2"
    format: AttributionFormat = "PDF"
    preview: bool = False


class PublicAttributionReportInput(_ReportOptions):
    """Input model for fossa_create_public_attribution_report."""

    format: AttributionFormat = "HTML"
    recipient_email: str | None = None

    @model_validator(mode="after")
    def _validate_recipient_email(self) -> "PublicAttributionReportInput":
        if self.recipient_email is not None and "@" not in self.recipient_email:
            raise ValueError("recipient_email must be an email address")
        return self


class RevisionDependenciesV1Input(_RevisionInput):
    """Input model for fossa_list_revision_dependencies_v1."""

    # FOSSA clamps `limit` to 25-100 server-side; rejecting out-of-range values
    # here keeps the answer from quietly differing from the request.
    limit: int = Field(default=100, ge=25, le=100)
    offset: int = Field(default=0, ge=0)
    dependency_locators: list[str] | None = None
    include_ignored: bool = False
    include_hash_data: bool = False
    include_license_text: bool = False
    transport: DependencyTransport = "auto"

    @model_validator(mode="after")
    def _validate_dependency_locators(self) -> "RevisionDependenciesV1Input":
        if self.dependency_locators is None:
            return self
        if not self.dependency_locators:
            raise ValueError("dependency_locators must name at least one locator when provided")
        if any(not locator.strip() for locator in self.dependency_locators):
            raise ValueError("dependency_locators must not contain blank entries")
        return self


class RevisionUpdateInput(_RevisionInput):
    """Input model for fossa_update_revision."""

    link: str | None = None
    url: str | None = None
    author: str | None = None

    @model_validator(mode="after")
    def _validate_at_least_one_field(self) -> "RevisionUpdateInput":
        if self.link is None and self.url is None and self.author is None:
            raise ValueError("Set at least one of link, url, or author")
        return self
