"""Unit tests for the local security policy overlay engine.

The load-bearing property under test is that the overlay is tighten-only: it can
add blocks FOSSA does not raise, and it can never clear a block FOSSA does.
"""

import json
from datetime import date

import pytest

from fossa_mcp.errors import FossaPolicyError
from fossa_mcp.policy import (
    FossaSecurityBaseline,
    PolicyDocument,
    evaluate_dependencies,
    load_policy_document,
    normalize_vuln_id,
    severity_for_cvss,
    split_locator,
)

TODAY = date(2026, 7, 31)

BASELINE = FossaSecurityBaseline(
    project_locator="git+github.com/acme/widget",
    security_policy_id=7,
    security_issue_scanning_enabled=True,
    security_status_check_enabled=True,
)

SCANNING_OFF = FossaSecurityBaseline(
    project_locator="git+github.com/acme/widget",
    security_policy_id=7,
    security_issue_scanning_enabled=False,
)


def dependency(locator, *, issues=None, title=None, depth=1):
    """Build a dependency record shaped like FOSSA's dependencies response."""
    return {
        "locator": locator,
        "title": title or split_locator(locator)[1],
        "depth": depth,
        "issues": issues or [],
    }


def vuln(vuln_id, cvss, *, status="active"):
    """Build an active vulnerability issue record, suffixed the way FOSSA does."""
    return {
        "type": "vulnerability",
        "status": status,
        "vulnId": vuln_id,
        "cvssScore": cvss,
    }


def document(**rules):
    """Build a single-policy overlay document from bare rule kwargs."""
    exceptions = rules.pop("exceptions", [])
    return PolicyDocument.model_validate(
        {
            "version": 1,
            "security": [{"id": "test-policy", "rules": rules, "exceptions": exceptions}],
        }
    )


def evaluate(dependencies, doc=None, baseline=BASELINE, today=TODAY):
    """Run the engine with the fixtures' defaults filled in."""
    return evaluate_dependencies(
        revision_locator="git+github.com/acme/widget$abc123",
        dependencies=dependencies,
        baseline=baseline,
        document=doc,
        today=today,
    )


# --- helpers -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.8, "critical"),
        (9.0, "critical"),
        (8.7, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.1, "low"),
        (0.0, "unknown"),
        (None, "unknown"),
    ],
)
def test_severity_for_cvss_uses_cvss_v3_bands(score, expected):
    assert severity_for_cvss(score) == expected


@pytest.mark.parametrize(
    ("locator", "expected"),
    [
        ("pip+mcp$1.6.0", ("pip", "mcp", "1.6.0")),
        ("pip+mcp", ("pip", "mcp", None)),
        ("mcp", (None, "mcp", None)),
        ("mcp$1.6.0", (None, "mcp", "1.6.0")),
    ],
)
def test_split_locator(locator, expected):
    assert split_locator(locator) == expected


def test_normalize_vuln_id_strips_fossa_package_suffix():
    assert normalize_vuln_id("CVE-2025-53365_pip+mcp") == "CVE-2025-53365"
    assert normalize_vuln_id("cve-2025-53365") == "CVE-2025-53365"


# --- baseline ----------------------------------------------------------------


def test_active_fossa_vulnerability_blocks_with_no_overlay_at_all():
    result = evaluate([dependency("pip+mcp$1.6.0", issues=[vuln("CVE-2025-53365_pip+mcp", 8.7)])])

    assert result.verdict == "block"
    assert [pkg.locator for pkg in result.blocked] == ["pip+mcp$1.6.0"]
    violation = result.blocked[0].violations[0]
    assert violation.source == "fossa"
    assert violation.vuln_id == "CVE-2025-53365"
    assert violation.severity == "high"


def test_ignored_fossa_issue_does_not_block():
    result = evaluate([dependency("pip+mcp$1.6.0", issues=[vuln("CVE-1", 8.7, status="ignored")])])

    assert result.verdict == "allow"
    assert result.allowed_count == 1


def test_scanning_disabled_means_fossa_contributes_no_baseline_block():
    """FOSSA raises no issues when scanning is off, so stale records must not block."""
    result = evaluate(
        [dependency("pip+mcp$1.6.0", issues=[vuln("CVE-1", 9.9)])],
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "allow"


def test_clean_dependency_is_allowed_and_not_enumerated():
    result = evaluate([dependency("pip+requests$2.31")])

    assert result.verdict == "allow"
    assert result.allowed_count == 1
    assert result.blocked == []
    assert result.warned == []


# --- overlay rules -----------------------------------------------------------


def test_max_cvss_blocks_a_package_fossa_allows():
    dep = dependency("pip+lodash$4.17.20", issues=[])
    fossa_clean = evaluate([dep])
    assert fossa_clean.verdict == "allow"

    dep_with_finding = dependency("pip+lodash$4.17.20", issues=[vuln("CVE-9", 5.5)])
    result = evaluate([dep_with_finding], doc=document(max_cvss=4.0), baseline=SCANNING_OFF)

    assert result.verdict == "block"
    assert result.blocked[0].violations[0].rule == "test-policy/max_cvss"


def test_warn_cvss_warns_without_blocking():
    result = evaluate(
        [dependency("pip+lodash$4.17.20", issues=[vuln("CVE-9", 5.5)])],
        doc=document(max_cvss=7.0, warn_cvss=4.0),
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "warn"
    assert result.warned[0].violations[0].rule == "test-policy/warn_cvss"
    assert result.blocked == []


def test_deny_severity_blocks_matching_band():
    result = evaluate(
        [dependency("pip+mcp$1.6.0", issues=[vuln("CVE-1", 8.7)])],
        doc=document(deny_severity=["high", "critical"]),
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "block"
    assert any(v.rule == "test-policy/deny_severity" for v in result.blocked[0].violations)


def test_denied_cve_matches_despite_fossa_package_suffix():
    result = evaluate(
        [dependency("pip+mcp$1.6.0", issues=[vuln("CVE-2025-53365_pip+mcp", 8.7)])],
        doc=document(denied_cves=["CVE-2025-53365"]),
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "block"
    assert any(v.rule == "test-policy/denied_cves" for v in result.blocked[0].violations)


def test_denied_packages_blocks_a_package_with_no_findings_at_all():
    result = evaluate(
        [dependency("pip+left-pad$1.0.0")],
        doc=document(denied_packages=["left-pad"]),
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "block"
    assert result.blocked[0].violations[0].rule == "test-policy/denied_packages"


@pytest.mark.parametrize(
    ("pattern", "should_match"),
    [
        ("pip+mcp$1.6.0", True),
        ("pip+mcp", True),
        ("mcp", True),
        ("PIP+MCP", True),
        ("pip+mcp$1.7.0", False),
        ("npm+mcp", False),
        ("mcp-server", False),
    ],
)
def test_denied_package_pattern_specificity(pattern, should_match):
    result = evaluate(
        [dependency("pip+mcp$1.6.0")],
        doc=document(denied_packages=[pattern]),
        baseline=SCANNING_OFF,
    )

    assert (result.verdict == "block") is should_match


def test_disabled_policy_is_not_applied():
    doc = PolicyDocument.model_validate(
        {
            "version": 1,
            "security": [
                {"id": "off", "enabled": False, "rules": {"denied_packages": ["mcp"]}},
            ],
        }
    )
    result = evaluate([dependency("pip+mcp$1.6.0")], doc=doc, baseline=SCANNING_OFF)

    assert result.verdict == "allow"
    assert result.applied_policy_ids == []


# --- tighten-only ------------------------------------------------------------


def test_exception_cannot_clear_a_fossa_baseline_block():
    """The central guarantee: a local exception never overrides a live FOSSA finding."""
    doc = document(
        denied_packages=["mcp"],
        exceptions=[{"package": "pip+mcp$1.6.0", "reason": "accepted risk"}],
    )
    result = evaluate(
        [dependency("pip+mcp$1.6.0", issues=[vuln("CVE-2025-53365_pip+mcp", 8.7)])],
        doc=doc,
    )

    assert result.verdict == "block"
    sources = {v.source for v in result.blocked[0].violations}
    assert sources == {"fossa"}
    assert result.blocked[0].applied_exception is not None


def test_exception_does_clear_an_overlay_only_block():
    doc = document(
        denied_packages=["mcp"],
        exceptions=[{"package": "pip+mcp$1.6.0", "reason": "vendored fork, patched"}],
    )
    result = evaluate([dependency("pip+mcp$1.6.0")], doc=doc, baseline=SCANNING_OFF)

    assert result.verdict == "allow"


def test_expired_exception_stops_applying_and_is_reported():
    doc = document(
        denied_packages=["mcp"],
        exceptions=[
            {"package": "mcp", "reason": "temporary", "expires": "2026-03-01"},
        ],
    )
    result = evaluate([dependency("pip+mcp$1.6.0")], doc=doc, baseline=SCANNING_OFF)

    assert result.verdict == "block"
    assert result.blocked[0].applied_exception is None
    assert len(result.blocked[0].expired_exceptions) == 1
    assert result.blocked[0].expired_exceptions[0].reason == "temporary"


def test_exception_on_its_expiry_date_still_applies():
    doc = document(
        denied_packages=["mcp"],
        exceptions=[{"package": "mcp", "reason": "grace", "expires": "2026-07-31"}],
    )
    result = evaluate([dependency("pip+mcp$1.6.0")], doc=doc, baseline=SCANNING_OFF)

    assert result.verdict == "allow"


def test_exception_requires_a_reason():
    with pytest.raises(ValueError):
        PolicyDocument.model_validate(
            {
                "version": 1,
                "security": [
                    {"id": "p", "exceptions": [{"package": "mcp", "reason": ""}]},
                ],
            }
        )


# --- aggregation -------------------------------------------------------------


def test_overall_verdict_is_the_worst_package_verdict():
    doc = document(warn_cvss=4.0)
    result = evaluate(
        [
            dependency("pip+requests$2.31"),
            dependency("pip+lodash$4.17.20", issues=[vuln("CVE-9", 5.5)]),
        ],
        doc=doc,
        baseline=SCANNING_OFF,
    )

    assert result.verdict == "warn"
    assert result.evaluated_count == 2
    assert result.allowed_count == 1

    result_with_block = evaluate(
        [
            dependency("pip+requests$2.31"),
            dependency("pip+lodash$4.17.20", issues=[vuln("CVE-9", 5.5)]),
            dependency("pip+mcp$1.6.0", issues=[vuln("CVE-1", 8.7)]),
        ],
        doc=doc,
    )
    assert result_with_block.verdict == "block"


# --- document loading --------------------------------------------------------


def test_load_returns_none_when_unconfigured():
    assert load_policy_document(None) is None


def test_load_reads_a_valid_document(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "security": [{"id": "baseline", "rules": {"max_cvss": 7.0}}],
            }
        )
    )

    doc = load_policy_document(str(path))

    assert doc is not None
    assert doc.security[0].rules.max_cvss == 7.0


def test_missing_policy_file_raises_rather_than_silently_disabling_policy(tmp_path):
    with pytest.raises(FossaPolicyError, match="Cannot read policy file"):
        load_policy_document(str(tmp_path / "absent.json"))


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{not json")

    with pytest.raises(FossaPolicyError, match="not valid JSON"):
        load_policy_document(str(path))


def test_unknown_policy_key_is_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({"version": 1, "security": [{"id": "p", "rules": {"max_cvs": 7.0}}]})
    )

    with pytest.raises(FossaPolicyError, match="not a valid policy"):
        load_policy_document(str(path))


def test_duplicate_policy_ids_are_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "security": [{"id": "p"}, {"id": "p"}]}))

    with pytest.raises(FossaPolicyError, match="unique"):
        load_policy_document(str(path))
