"""Tests for cross-field validation rules on FOSSA MCP input models."""

import pytest
from pydantic import ValidationError

from fossa_mcp.models import IssueListInput


def test_global_scope_rejects_project_locator():
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", scope_type="global", project_locator="p")


def test_global_scope_rejects_revision_locator():
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", scope_type="global", revision_locator="r")


def test_project_scope_requires_project_locator():
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", scope_type="project", revision_locator="r")


def test_project_scope_requires_revision_locator():
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", scope_type="project", project_locator="p")


def test_project_scope_with_both_locators_is_valid():
    model = IssueListInput(
        category="licensing", scope_type="project", project_locator="p", revision_locator="r"
    )
    assert model.project_locator == "p"


def test_compare_to_revision_requires_change_status():
    with pytest.raises(ValidationError):
        IssueListInput(
            category="licensing",
            scope_type="project",
            project_locator="p",
            revision_locator="r",
            compare_to_revision="old",
        )


def test_change_status_requires_compare_to_revision():
    with pytest.raises(ValidationError):
        IssueListInput(
            category="licensing",
            scope_type="project",
            project_locator="p",
            revision_locator="r",
            change_status="new",
        )


def test_compare_to_revision_and_change_status_together_is_valid():
    model = IssueListInput(
        category="licensing",
        scope_type="project",
        project_locator="p",
        revision_locator="r",
        compare_to_revision="old",
        change_status="new",
    )
    assert model.change_status == "new"


@pytest.mark.parametrize(
    "field,value",
    [("severity", ["critical"]), ("severity_source", ["standard"]), ("cwes", ["CWE-1"])],
)
def test_vulnerability_only_filters_rejected_for_other_categories(field, value):
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", **{field: value})


def test_severity_allowed_for_vulnerability_category():
    model = IssueListInput(category="vulnerability", severity=["critical", "high"])
    assert model.severity == ["critical", "high"]


def test_issue_types_rejected_for_vulnerability_category():
    with pytest.raises(ValidationError):
        IssueListInput(category="vulnerability", issue_types=["some-type"])


def test_issue_types_allowed_for_licensing_category():
    model = IssueListInput(category="licensing", issue_types=["some-type"])
    assert model.issue_types == ["some-type"]


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        IssueListInput(category="licensing", unexpected_field=1)  # type: ignore[call-arg]
