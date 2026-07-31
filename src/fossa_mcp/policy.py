"""Local security policy overlay, evaluated on top of FOSSA's own findings.

The overlay is deliberately **tighten-only**. FOSSA remains the baseline
authority: if FOSSA's assigned security policy raised an active vulnerability
issue against a dependency, that dependency is blocked and nothing in this file
can clear it. The overlay exists to block things FOSSA currently allows —
a stricter CVSS ceiling, a banned CVE, a banned package — for teams whose bar
sits above their org-wide FOSSA policy.

That asymmetry is the whole point and is enforced in `evaluate_dependencies`:
an `exception` entry suppresses a block this overlay introduced, and never a
block FOSSA introduced. An allowlist that could wave through a live FOSSA
finding would not be an overlay, it would be a bypass.

The policy document is JSON. YAML would read better, but every runtime
dependency in this project is accounted for in NOTICE and the generated
third-party license file (see DECISIONS.md §3), and a nicer policy file syntax
does not justify adding to that tree.
"""

import json
from datetime import date
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import FossaPolicyError
from .models import Severity

Verdict = Literal["allow", "warn", "block"]

# CVSS v3 qualitative severity bands, high to low. FOSSA reports a numeric
# `cvssScore` on issue records but not always a qualitative band, so derive it.
_CVSS_SEVERITY_FLOORS: tuple[tuple[float, Severity], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def severity_for_cvss(score: float | None) -> Severity:
    """Map a CVSS base score onto its qualitative band.

    Returns `"unknown"` for a missing score rather than guessing `"low"`: an
    unscored vulnerability is unassessed, not harmless.
    """
    if score is None:
        return "unknown"
    for floor, severity in _CVSS_SEVERITY_FLOORS:
        if score >= floor:
            return severity
    return "unknown"


def split_locator(locator: str) -> tuple[str | None, str, str | None]:
    """Split a FOSSA dependency locator into `(fetcher, name, version)`.

    Locators look like `pip+mcp$1.6.0`. Either affix may be absent, so this
    tolerates `mcp`, `pip+mcp`, and `mcp$1.6.0` too.
    """
    remainder, separator, version = locator.partition("$")
    fetcher, plus, name = remainder.partition("+")
    if not plus:
        return None, remainder, version if separator else None
    return fetcher, name, version if separator else None


def _matches_package(locator: str, pattern: str) -> bool:
    """Report whether a dependency locator is addressed by a policy pattern.

    A pattern may be a full locator (`pip+mcp$1.6.0`, exact version), a
    fetcher-qualified name (`pip+mcp`, any version), or a bare name (`mcp`, any
    fetcher and version). Matching is case-insensitive because package
    ecosystems disagree about case and a policy author should not have to care.
    """
    locator_l = locator.strip().lower()
    pattern_l = pattern.strip().lower()

    if locator_l == pattern_l:
        return True

    dep_fetcher, dep_name, _ = split_locator(locator_l)
    pat_fetcher, pat_name, pat_version = split_locator(pattern_l)

    if pat_version is not None:
        # The pattern pinned a version and it did not match exactly above.
        return False
    if pat_fetcher is not None and pat_fetcher != dep_fetcher:
        return False
    return pat_name == dep_name


def normalize_vuln_id(vuln_id: str) -> str:
    """Strip FOSSA's package suffix from a vulnerability id.

    FOSSA reports `CVE-2025-53365_pip+mcp` — the advisory id with the affected
    package appended. Policy authors write `CVE-2025-53365`, so compare on the
    advisory id alone.
    """
    return vuln_id.split("_", 1)[0].strip().upper()


class PolicyException(BaseModel):
    """A time-boxed, justified suppression of an overlay-introduced block.

    Never suppresses a FOSSA-introduced block — see the module docstring.
    """

    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, description="Locator, fetcher+name, or bare package name")
    reason: str = Field(
        min_length=1, description="Why this package is excepted; required, not decorative"
    )
    expires: date | None = Field(
        default=None, description="Last day the exception applies; omit for a permanent exception"
    )

    def is_expired(self, today: date) -> bool:
        """Report whether this exception has lapsed as of `today`."""
        return self.expires is not None and today > self.expires


class SecurityRules(BaseModel):
    """The conditions under which the overlay blocks or warns on a package."""

    model_config = ConfigDict(extra="forbid")

    max_cvss: float | None = Field(
        default=None, ge=0.0, le=10.0, description="Block at or above this CVSS base score"
    )
    warn_cvss: float | None = Field(
        default=None, ge=0.0, le=10.0, description="Warn at or above this CVSS base score"
    )
    deny_severity: list[Severity] = Field(
        default_factory=list,
        description="Block any package carrying a vulnerability in these bands",
    )
    denied_cves: list[str] = Field(
        default_factory=list, description="Block these advisory ids outright"
    )
    denied_packages: list[str] = Field(
        default_factory=list, description="Block these packages regardless of findings"
    )

    @field_validator("deny_severity")
    @classmethod
    def _reject_duplicate_severities(cls, value: list[Severity]) -> list[Severity]:
        if len(set(value)) != len(value):
            raise ValueError("deny_severity contains duplicates")
        return value


class SecurityPolicy(BaseModel):
    """One named overlay policy."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    description: str | None = None
    enabled: bool = True
    rules: SecurityRules = Field(default_factory=SecurityRules)
    exceptions: list[PolicyException] = Field(default_factory=list)


class PolicyDocument(BaseModel):
    """The parsed contents of the file named by `FOSSA_POLICY_FILE`."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    security: list[SecurityPolicy] = Field(default_factory=list)

    @field_validator("security")
    @classmethod
    def _reject_duplicate_ids(cls, value: list[SecurityPolicy]) -> list[SecurityPolicy]:
        ids = [policy.id for policy in value]
        if len(set(ids)) != len(ids):
            raise ValueError("security policy ids must be unique")
        return value

    def enabled_security_policies(self) -> list[SecurityPolicy]:
        """Return only the security policies the operator has switched on."""
        return [policy for policy in self.security if policy.enabled]


def load_policy_document(path: str | None) -> PolicyDocument | None:
    """Load and validate the local policy overlay.

    Returns `None` when no policy file is configured, which is a supported
    state: the server then reports FOSSA's baseline verdicts unmodified.

    Raises:
        FossaPolicyError: If a path is configured but missing, unreadable, not
            valid JSON, or not a valid policy document. A configured-but-broken
            policy file is never silently downgraded to "no policy" — that would
            turn a typo into a silently weaker security posture.
    """
    if path is None:
        return None

    policy_path = Path(path).expanduser()

    try:
        raw = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FossaPolicyError(f"Cannot read policy file {policy_path}: {exc}") from exc

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FossaPolicyError(f"Policy file {policy_path} is not valid JSON: {exc}") from exc

    try:
        return PolicyDocument.model_validate(parsed)
    except Exception as exc:
        raise FossaPolicyError(f"Policy file {policy_path} is not a valid policy: {exc}") from exc


class FossaSecurityBaseline(BaseModel):
    """What FOSSA itself is configured to enforce for one project.

    `status_check_filter_vulnerability` is FOSSA's severity threshold for the
    CI status check. Its integer scale is undocumented in the vendored OpenAPI
    spec, so it is carried through verbatim and never interpreted here.
    """

    model_config = ConfigDict(extra="forbid")

    project_locator: str
    security_policy_id: int | None = None
    org_default_security_policy_id: int | None = None
    security_issue_scanning_enabled: bool | None = None
    security_status_check_enabled: bool | None = None
    status_check_filter_vulnerability: int | None = None

    @property
    def effective_policy_id(self) -> int | None:
        """The policy actually in force: the project's, else the org default."""
        if self.security_policy_id is not None:
            return self.security_policy_id
        return self.org_default_security_policy_id

    @property
    def enforces_blocks(self) -> bool:
        """Whether FOSSA findings currently gate anything for this project.

        Scanning off means FOSSA raises no issues at all, so its baseline
        blocks nothing and the overlay is the only thing evaluating.
        """
        return self.security_issue_scanning_enabled is not False


class Violation(BaseModel):
    """One reason a package received the verdict it did."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["fossa", "overlay"]
    rule: str
    detail: str
    severity: Severity = "unknown"
    cvss_score: float | None = None
    vuln_id: str | None = None


class PackageVerdict(BaseModel):
    """The evaluated outcome for a single dependency."""

    model_config = ConfigDict(extra="forbid")

    locator: str
    title: str | None = None
    depth: int | None = None
    verdict: Verdict
    violations: list[Violation] = Field(default_factory=list)
    applied_exception: PolicyException | None = None
    expired_exceptions: list[PolicyException] = Field(default_factory=list)


class PolicyEvaluation(BaseModel):
    """The result of evaluating every dependency in a revision."""

    model_config = ConfigDict(extra="forbid")

    revision_locator: str
    verdict: Verdict
    baseline: FossaSecurityBaseline
    applied_policy_ids: list[str] = Field(default_factory=list)
    evaluated_count: int = 0
    blocked: list[PackageVerdict] = Field(default_factory=list)
    warned: list[PackageVerdict] = Field(default_factory=list)
    allowed_count: int = 0


def _active_vulnerabilities(dependency: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the dependency's active vulnerability issue records."""
    issues = dependency.get("issues")
    if not isinstance(issues, list):
        return []
    return [
        issue
        for issue in issues
        if isinstance(issue, dict)
        and issue.get("type") == "vulnerability"
        and issue.get("status") == "active"
    ]


def _cvss_of(issue: dict[str, Any]) -> float | None:
    """Read an issue's CVSS score, tolerating absent or non-numeric values."""
    score = issue.get("cvssScore")
    if isinstance(score, bool) or not isinstance(score, int | float):
        return None
    return float(score)


def _baseline_violations(dependency: dict[str, Any]) -> list[Violation]:
    """Every active FOSSA vulnerability finding on this dependency.

    An active vulnerability issue means FOSSA's assigned security policy already
    raised it, so each one is a baseline block that the overlay cannot clear.
    """
    violations: list[Violation] = []
    for issue in _active_vulnerabilities(dependency):
        raw_vuln_id = issue.get("vulnId")
        vuln_id = normalize_vuln_id(raw_vuln_id) if isinstance(raw_vuln_id, str) else None
        score = _cvss_of(issue)
        violations.append(
            Violation(
                source="fossa",
                rule="fossa_security_policy",
                detail=(
                    f"FOSSA raised active vulnerability issue "
                    f"{vuln_id or issue.get('id', 'unknown')}"
                ),
                severity=severity_for_cvss(score),
                cvss_score=score,
                vuln_id=vuln_id,
            )
        )
    return violations


def _overlay_violations(
    dependency: dict[str, Any], policy: SecurityPolicy
) -> tuple[list[Violation], list[Violation]]:
    """Apply one overlay policy, returning `(blocking, warning)` violations."""
    locator = str(dependency.get("locator", ""))
    rules = policy.rules
    blocking: list[Violation] = []
    warning: list[Violation] = []

    for pattern in rules.denied_packages:
        if _matches_package(locator, pattern):
            blocking.append(
                Violation(
                    source="overlay",
                    rule=f"{policy.id}/denied_packages",
                    detail=f"{locator} matches denied package pattern {pattern!r}",
                )
            )

    denied_cves = {normalize_vuln_id(cve) for cve in rules.denied_cves}
    deny_severity = set(rules.deny_severity)

    for issue in _active_vulnerabilities(dependency):
        raw_vuln_id = issue.get("vulnId")
        vuln_id = normalize_vuln_id(raw_vuln_id) if isinstance(raw_vuln_id, str) else None
        score = _cvss_of(issue)
        severity = severity_for_cvss(score)

        if vuln_id is not None and vuln_id in denied_cves:
            blocking.append(
                Violation(
                    source="overlay",
                    rule=f"{policy.id}/denied_cves",
                    detail=f"{vuln_id} is denied outright",
                    severity=severity,
                    cvss_score=score,
                    vuln_id=vuln_id,
                )
            )

        if severity in deny_severity:
            blocking.append(
                Violation(
                    source="overlay",
                    rule=f"{policy.id}/deny_severity",
                    detail=f"{vuln_id or 'vulnerability'} is {severity} severity",
                    severity=severity,
                    cvss_score=score,
                    vuln_id=vuln_id,
                )
            )

        if score is None:
            continue

        if rules.max_cvss is not None and score >= rules.max_cvss:
            blocking.append(
                Violation(
                    source="overlay",
                    rule=f"{policy.id}/max_cvss",
                    detail=f"CVSS {score} is at or above the {rules.max_cvss} ceiling",
                    severity=severity,
                    cvss_score=score,
                    vuln_id=vuln_id,
                )
            )
        elif rules.warn_cvss is not None and score >= rules.warn_cvss:
            warning.append(
                Violation(
                    source="overlay",
                    rule=f"{policy.id}/warn_cvss",
                    detail=f"CVSS {score} is at or above the {rules.warn_cvss} warning line",
                    severity=severity,
                    cvss_score=score,
                    vuln_id=vuln_id,
                )
            )

    return blocking, warning


def _find_exception(
    locator: str, policies: list[SecurityPolicy], today: date
) -> tuple[PolicyException | None, list[PolicyException]]:
    """Find the first live exception for a locator, plus any expired matches.

    Expired matches are returned rather than dropped so the caller can say
    "this was excepted until March" instead of silently reverting to a block
    that looks like it appeared from nowhere.
    """
    expired: list[PolicyException] = []
    for policy in policies:
        for exception in policy.exceptions:
            if not _matches_package(locator, exception.package):
                continue
            if exception.is_expired(today):
                expired.append(exception)
                continue
            return exception, expired
    return None, expired


def evaluate_dependencies(
    *,
    revision_locator: str,
    dependencies: list[dict[str, Any]],
    baseline: FossaSecurityBaseline,
    document: PolicyDocument | None,
    today: date,
) -> PolicyEvaluation:
    """Evaluate a revision's dependencies against FOSSA's baseline plus the overlay.

    Precedence, in order:

    1. A FOSSA-raised active vulnerability blocks. Always. No exception clears it.
    2. An overlay rule blocks, unless a live exception covers the package.
    3. An overlay warning warns.
    4. Otherwise the package is allowed.
    """
    policies = document.enabled_security_policies() if document is not None else []

    blocked: list[PackageVerdict] = []
    warned: list[PackageVerdict] = []
    allowed_count = 0

    for dependency in dependencies:
        locator = str(dependency.get("locator", ""))

        baseline_violations = _baseline_violations(dependency) if baseline.enforces_blocks else []

        overlay_blocking: list[Violation] = []
        overlay_warning: list[Violation] = []
        for policy in policies:
            policy_blocking, policy_warning = _overlay_violations(dependency, policy)
            overlay_blocking.extend(policy_blocking)
            overlay_warning.extend(policy_warning)

        exception, expired = _find_exception(locator, policies, today)

        # An exception only ever suppresses overlay findings. Baseline findings
        # survive it — that is what makes this overlay tighten-only.
        if exception is not None:
            overlay_blocking = []
            overlay_warning = []

        violations = baseline_violations + overlay_blocking + overlay_warning

        if baseline_violations or overlay_blocking:
            verdict: Verdict = "block"
        elif overlay_warning:
            verdict = "warn"
        else:
            verdict = "allow"

        if verdict == "allow":
            allowed_count += 1
            continue

        depth = dependency.get("depth")
        title = dependency.get("title")
        package_verdict = PackageVerdict(
            locator=locator,
            title=title if isinstance(title, str) else None,
            depth=depth if isinstance(depth, int) else None,
            verdict=verdict,
            violations=violations,
            applied_exception=exception,
            expired_exceptions=expired,
        )

        if verdict == "block":
            blocked.append(package_verdict)
        else:
            warned.append(package_verdict)

    overall: Verdict = "allow"
    if blocked:
        overall = "block"
    elif warned:
        overall = "warn"

    return PolicyEvaluation(
        revision_locator=revision_locator,
        verdict=overall,
        baseline=baseline,
        applied_policy_ids=[policy.id for policy in policies],
        evaluated_count=len(dependencies),
        blocked=blocked,
        warned=warned,
        allowed_count=allowed_count,
    )


__all__ = [
    "FossaSecurityBaseline",
    "PackageVerdict",
    "PolicyDocument",
    "PolicyEvaluation",
    "PolicyException",
    "SecurityPolicy",
    "SecurityRules",
    "Verdict",
    "Violation",
    "evaluate_dependencies",
    "load_policy_document",
    "normalize_vuln_id",
    "severity_for_cvss",
    "split_locator",
]
