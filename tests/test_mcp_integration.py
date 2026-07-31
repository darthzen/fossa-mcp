"""In-memory MCP protocol integration tests for the FOSSA MCP server.

Uses `mcp.shared.memory.create_connected_server_and_client_session` to drive
the real FastMCP server through an in-memory client session, so tool
registration, JSON schema validation, and MCP-level error surfacing
(`isError=True`) are exercised exactly as a real MCP client would see them.
"""

import logging
from typing import Any

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

from fossa_mcp.server import mcp
from fossa_mcp.server import settings as server_settings

PROJECT = "git+github.com/acme/widget"

EXPECTED_READ_ONLY_TOOL_NAMES = {
    # projects
    "fossa_list_projects",
    "fossa_get_project",
    "fossa_get_projects_summary",
    "fossa_get_project_associations",
    "fossa_export_project_issues",
    # revisions
    "fossa_list_project_revisions",
    "fossa_list_revision_scans",
    "fossa_get_revision_notice_files",
    "fossa_get_revision_sbom",
    "fossa_get_revision_remediation_guidance",
    "fossa_get_revision_attribution_json",
    "fossa_render_revision_attribution",
    "fossa_list_revision_dependencies_v1",
    # dependencies
    "fossa_list_dependencies",
    "fossa_get_dependency",
    # issues, issue overview, saved issue filters
    "fossa_list_issues",
    "fossa_get_issue",
    "fossa_get_issue_facets",
    "fossa_list_issue_revisions",
    "fossa_compare_issue_summaries",
    "fossa_get_issue_affected_projects",
    "fossa_export_global_issues_csv",
    "fossa_get_issue_exceptions",
    "fossa_get_issue_overview",
    "fossa_get_issue_filters",
    # release groups
    "fossa_get_release_group",
    "fossa_list_release_group_releases",
    "fossa_get_release_group_release",
    "fossa_get_release_group_attribution_report",
    "fossa_get_release_group_attribution_status",
    # posture, reports, security policy
    "fossa_project_posture",
    "fossa_get_attribution_report",
    "fossa_get_security_policy",
    "fossa_evaluate_security_policy",
    # teams, team groups, roles, users
    "fossa_list_teams",
    "fossa_get_team",
    "fossa_list_addable_team_targets",
    "fossa_get_team_groups",
    "fossa_list_roles",
    "fossa_list_users",
    # package labels, assignments, organization labels
    "fossa_list_package_labels",
    "fossa_list_package_label_assignments",
    "fossa_list_organization_labels",
    # organization settings and limits
    "fossa_org_settings",
    "fossa_org_limits",
    # federated identity
    "fossa_list_oidc_providers",
    "fossa_get_oidc_provider",
    "fossa_list_oidc_provider_service_accounts",
    "fossa_list_oidc_trust_relationships",
    "fossa_get_oidc_trust_relationship",
    # integrations
    "fossa_get_jira_configurations",
    "fossa_get_fossabot_status",
    "fossa_list_fossabot_upgrade_prs",
    "fossa_get_fossabot_upgrade_pr",
    "fossa_list_report_options",
    "fossa_list_snippets",
    "fossa_get_snippet",
    # inventory
    "fossa_binary_components",
    "fossa_binary_dependency_confidence",
    "fossa_binary_revision_detail",
    "fossa_list_packages",
    "fossa_package_observability",
    # Two GETs that leave FOSSA unchanged and are therefore read-only here, even
    # though one of them queues an email: neither is behind the write gate, and
    # this set is what the gate covers.
    "fossa_export_package_index",
    "fossa_get_component_upload_url",
    "fossa_get_audit_logs",
    "fossa_get_sbom_sharing",
    "fossa_get_builds",
    "fossa_search_cves",
    "fossa_get_vulnerability_remediation",
    "fossa_get_cli_organization",
    "fossa_get_github_app_installation_url",
}

# Every tool permitted to modify FOSSA state. Adding a name here is a deliberate
# act — see DECISIONS.md §5, which records why the server stopped being wholly
# read-only, and §7 for the tiering. A tool that writes must be listed here and
# must advertise readOnlyHint=False, or this test fails.
EXPECTED_WRITE_TOOL_NAMES = {
    # projects
    "fossa_update_project",
    "fossa_apply_project_label",
    "fossa_generate_project_attribution_slug",
    "fossa_delete_project_attribution_slug",
    "fossa_delete_project",
    "fossa_delete_projects",
    # revisions
    "fossa_update_revision",
    "fossa_email_revision_attribution",
    "fossa_create_public_attribution_report",
    # issues
    "fossa_update_issues",
    "fossa_extend_issue_exception",
    "fossa_delete_issue_exceptions",
    "fossa_create_issue_dispute",
    "fossa_export_issue_overview",
    "fossa_save_issue_filter",
    "fossa_delete_issue_filter",
    # release groups
    "fossa_create_release_group",
    "fossa_update_release_group",
    "fossa_delete_release_group",
    "fossa_create_release_group_release",
    "fossa_update_release_group_release",
    "fossa_delete_release_group_release",
    "fossa_queue_release_group_attribution_report",
    # security policy
    "fossa_enable_security_policy",
    "fossa_assign_security_policy_to_projects",
    # teams, team groups, roles, users
    "fossa_create_team",
    "fossa_update_team",
    "fossa_delete_team",
    "fossa_update_team_assignments",
    "fossa_manage_team_group",
    "fossa_update_team_group_assignments",
    "fossa_manage_role",
    "fossa_create_service_account",
    # package labels, assignments, organization labels
    "fossa_create_package_labels",
    "fossa_delete_package_labels",
    "fossa_assign_package_labels",
    "fossa_bulk_assign_package_label",
    "fossa_set_package_label_assignments",
    "fossa_unassign_package_labels",
    "fossa_create_organization_label",
    "fossa_delete_organization_label",
    # organization settings
    "fossa_update_org_settings",
    "fossa_delete_org_setting",
    # federated identity
    "fossa_create_oidc_provider",
    "fossa_delete_oidc_provider",
    "fossa_create_oidc_trust_relationship",
    "fossa_update_oidc_trust_relationship",
    "fossa_delete_oidc_trust_relationship",
    "fossa_exchange_oidc_token",
    "fossa_update_saml_settings",
    "fossa_delete_saml_settings",
    # integrations
    "fossa_save_jira_configuration",
    "fossa_delete_jira_configuration",
    "fossa_request_fossabot_upgrade_pr",
    "fossa_save_report_option",
    "fossa_delete_report_option",
    "fossa_set_custom_risk_score",
    "fossa_delete_custom_risk_score",
    "fossa_set_snippet_rejection",
    # inventory
    "fossa_resolve_purls",
    "fossa_build_component",
    "fossa_export_audit_logs",
    "fossa_share_sbom_revision",
    "fossa_set_license_conclusion",
}

# The subset that must advertise destructiveHint=True: everything that removes
# state or replaces it wholesale, plus the tools whose target set can be a
# filter rather than an explicit list and the create/update/delete multiplexers,
# which have to advertise the worst action they can be asked to perform. A
# client may reasonably turn this hint into a confirmation prompt, so it is
# pinned rather than left to whichever annotation constant a registration
# picked up.
#
# Every name here also reaches `require_tier(..., WriteTier.DESTRUCTIVE, ...)`
# on the path that destroys — the domain suites pin that end of it.
EXPECTED_DESTRUCTIVE_TOOL_NAMES = {
    "fossa_delete_project_attribution_slug",
    "fossa_delete_project",
    "fossa_delete_projects",
    "fossa_delete_issue_exceptions",
    "fossa_delete_issue_filter",
    "fossa_delete_release_group",
    "fossa_delete_release_group_release",
    "fossa_update_issues",
    # teams: the delete, the two assignment tools whose "remove" and "replace"
    # actions take assignments away, and the two manage_* multiplexers
    "fossa_delete_team",
    "fossa_update_team_assignments",
    "fossa_manage_team_group",
    "fossa_update_team_group_assignments",
    "fossa_manage_role",
    # labels: the deletes, plus the reconcile that drops what its map omits
    "fossa_delete_package_labels",
    "fossa_set_package_label_assignments",
    "fossa_unassign_package_labels",
    "fossa_delete_organization_label",
    # organization settings: PUT replaces a section wholesale and "propagate"
    # overwrites the setting on every project in the organization
    "fossa_update_org_settings",
    "fossa_delete_org_setting",
    # federated identity
    "fossa_delete_oidc_provider",
    "fossa_delete_oidc_trust_relationship",
    "fossa_delete_saml_settings",
    # integrations
    "fossa_delete_jira_configuration",
    "fossa_delete_report_option",
    "fossa_delete_custom_risk_score",
    "fossa_set_snippet_rejection",
    # inventory: unconcluding removes a conclusion, and an organization-scoped
    # conclusion re-licenses every project at once
    "fossa_set_license_conclusion",
}

# One valid call per write tool, used to prove the write gate refuses before any
# HTTP request is made. The arguments must be valid: an argument that fails
# schema or model validation would also yield isError with zero HTTP calls, and
# would pass this test while proving nothing about the gate. The assertion on
# the error text is what keeps that distinction honest.
WRITE_TOOL_CALL_ARGUMENTS: dict[str, dict[str, Any]] = {
    "fossa_update_project": {"project_locator": PROJECT, "title": "Widget"},
    "fossa_apply_project_label": {"label_id": 3, "project_locators": [PROJECT]},
    "fossa_generate_project_attribution_slug": {"project_locator": PROJECT},
    "fossa_delete_project_attribution_slug": {"project_locator": PROJECT},
    "fossa_delete_project": {"project_locator": PROJECT},
    "fossa_delete_projects": {"project_locators": [PROJECT]},
    "fossa_update_revision": {
        "project_locator": PROJECT,
        "revision_locator": "abc123",
        "author": "release-bot",
    },
    "fossa_email_revision_attribution": {
        "project_locator": PROJECT,
        "revision_locator": "abc123",
    },
    "fossa_create_public_attribution_report": {
        "project_locator": PROJECT,
        "revision_locator": "abc123",
    },
    "fossa_update_issues": {"action": "ignore", "category": "licensing", "issue_ids": [11]},
    "fossa_extend_issue_exception": {"exception_id": 4, "expires_after": "2027-01-01"},
    "fossa_delete_issue_exceptions": {"exception_id": 4},
    "fossa_create_issue_dispute": {"issue_id": 11, "reason": "LICENSE_DETECTION_FALSE_POSITIVE"},
    "fossa_export_issue_overview": {"category": "licensing"},
    "fossa_save_issue_filter": {
        "name": "Copyleft in shipped code",
        "criteria": {"search": "gpl"},
        "category": "licensing",
    },
    "fossa_delete_issue_filter": {"filter_id": 4},
    "fossa_create_release_group": {
        "title": "Platform",
        "release_title": "2026.1",
        "projects": [{"projectId": PROJECT}],
    },
    "fossa_update_release_group": {"release_group_id": 1, "title": "Platform"},
    "fossa_delete_release_group": {"release_group_id": 1},
    "fossa_create_release_group_release": {
        "release_group_id": 1,
        "title": "2026.2",
        "projects": [{"projectId": PROJECT}],
    },
    "fossa_update_release_group_release": {
        "release_group_id": 1,
        "release_id": 2,
        "title": "2026.2",
    },
    "fossa_delete_release_group_release": {"release_group_id": 1, "release_id": 2},
    "fossa_queue_release_group_attribution_report": {"release_group_id": 1, "release_id": 2},
    "fossa_enable_security_policy": {"project_locator": PROJECT, "security_policy_id": 7},
    "fossa_assign_security_policy_to_projects": {
        "security_policy_id": 7,
        "project_locators": [PROJECT],
    },
    # teams, team groups, roles, users
    "fossa_create_team": {"name": "Engineering", "default_role_id": 2},
    "fossa_update_team": {"team_id": 7, "name": "Platform"},
    "fossa_delete_team": {"team_id": 7},
    "fossa_update_team_assignments": {
        "team_id": 7,
        "target": "users",
        "action": "add",
        "users": [{"id": 123, "roleId": 2}],
    },
    "fossa_manage_team_group": {"action": "create", "name": "Platform", "default_role_id": 2},
    "fossa_update_team_group_assignments": {
        "team_group_id": 3,
        "target": "teams",
        "action": "add",
        "team_ids": [7],
    },
    "fossa_manage_role": {
        "action": "create",
        "scope": "organization",
        "name": "Auditor",
        "description": "Read-only",
    },
    "fossa_create_service_account": {"username": "ci-bot", "org_role_id": 3},
    # package labels, assignments, organization labels
    "fossa_create_package_labels": {"labels": ["vendored"]},
    "fossa_delete_package_labels": {"label_ids": [4]},
    "fossa_assign_package_labels": {
        "package_id": "npm+left-pad",
        "scope": "org",
        "label_ids": [4],
        "package_version": "1.3.0",
    },
    "fossa_bulk_assign_package_label": {
        "label_id": 4,
        "package_locators": ["npm+left-pad$1.3.0"],
        "scope": "org",
    },
    "fossa_set_package_label_assignments": {
        "package_id": "npm+left-pad",
        "scope": "org",
        "new_label_ids": {"1.3.0": [4]},
    },
    "fossa_unassign_package_labels": {"assignment_ids": [9]},
    "fossa_create_organization_label": {"label": "shipped"},
    "fossa_delete_organization_label": {"label_id": 4},
    # organization settings
    "fossa_update_org_settings": {"section": "general", "values": {"title": "Acme"}},
    "fossa_delete_org_setting": {"target": "logo"},
    # federated identity. The two SAML tools resolve their organization id
    # before the gate runs, so it is passed rather than left to FOSSA_ORG_ID.
    "fossa_create_oidc_provider": {"issuer": "https://token.actions.example"},
    "fossa_delete_oidc_provider": {"provider_id": 42},
    "fossa_create_oidc_trust_relationship": {
        "user_id": 7,
        "provider_id": 42,
        "audiences": ["fossa"],
        "required_claims": [{"claim": "sub", "value": "repo:acme/widget:ref:refs/heads/main"}],
    },
    "fossa_update_oidc_trust_relationship": {
        "trust_relationship_id": 99,
        "audiences": ["fossa"],
    },
    "fossa_delete_oidc_trust_relationship": {"trust_relationship_id": 99},
    "fossa_exchange_oidc_token": {
        "provider_id": 42,
        "username": "ci-bot",
        "token": "header.payload.signature",
    },
    "fossa_update_saml_settings": {
        "entry_point": "https://sso.example/saml2",
        "cert": "-----BEGIN CERTIFICATE-----",
        "audience": "urn:acme",
        "organization_id": 1,
    },
    "fossa_delete_saml_settings": {"organization_id": 1},
    # integrations
    "fossa_save_jira_configuration": {
        "name": "Acme Jira",
        "base_url": "https://acme.atlassian.net",
    },
    "fossa_delete_jira_configuration": {"jira_id": 5},
    "fossa_request_fossabot_upgrade_pr": {"issue_id": 11},
    "fossa_save_report_option": {
        "name": "Release notice",
        "sections": ["licenseList"],
        "dependency_data": ["authors"],
        "use_hash_and_version_data": False,
        "exclude_package_labels": [4],
    },
    "fossa_delete_report_option": {"report_option_id": 6},
    "fossa_set_custom_risk_score": {
        "action": "create",
        "issue_id": 11,
        "scope_type": "project",
        "scope_id": PROJECT,
        "score": 80,
    },
    "fossa_delete_custom_risk_score": {
        "issue_id": 11,
        "scope_type": "project",
        "scope_id": PROJECT,
    },
    "fossa_set_snippet_rejection": {
        "project_locator": PROJECT,
        "revision_locator": "abc123",
        "rejected": True,
        "path": "/src/vendor",
        "snippet_ids": ["snip-1"],
    },
    # inventory
    "fossa_resolve_purls": {"purls": ["pkg:npm/left-pad@1.3.0"]},
    "fossa_build_component": {"package_spec": "archive+acme/widget", "revision": "1.0.0"},
    "fossa_export_audit_logs": {"start_date": "2026-01-01", "end_date": "2026-01-31"},
    "fossa_share_sbom_revision": {"revision_id": "abc123", "shared_organization_id": 2},
    "fossa_set_license_conclusion": {
        "action": "conclude",
        "dependency_revision_locator": "npm+left-pad$1.3.0",
        "scope": "project",
        "license_id": "MIT",
        "project_locator": PROJECT,
    },
}


def _error_text(result) -> str:
    return "\n".join(
        block.text for block in (result.content or []) if isinstance(block, TextContent)
    )


@pytest.mark.asyncio
async def test_tools_list_partitions_into_declared_read_and_write_tools():
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.list_tools()

    names = {tool.name for tool in result.tools}
    assert names == EXPECTED_READ_ONLY_TOOL_NAMES | EXPECTED_WRITE_TOOL_NAMES
    assert not EXPECTED_READ_ONLY_TOOL_NAMES & EXPECTED_WRITE_TOOL_NAMES
    assert EXPECTED_DESTRUCTIVE_TOOL_NAMES <= EXPECTED_WRITE_TOOL_NAMES

    for tool in result.tools:
        assert tool.annotations is not None
        expected_read_only = tool.name in EXPECTED_READ_ONLY_TOOL_NAMES
        assert tool.annotations.readOnlyHint is expected_read_only, (
            f"{tool.name} advertises readOnlyHint={tool.annotations.readOnlyHint}"
        )

        if expected_read_only:
            continue

        expected_destructive = tool.name in EXPECTED_DESTRUCTIVE_TOOL_NAMES
        assert tool.annotations.destructiveHint is expected_destructive, (
            f"{tool.name} advertises destructiveHint={tool.annotations.destructiveHint}"
        )


def test_every_write_tool_has_a_refusal_case():
    """Keep the refusal table from silently falling behind the write set."""
    assert set(WRITE_TOOL_CALL_ARGUMENTS) == EXPECTED_WRITE_TOOL_NAMES


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", sorted(WRITE_TOOL_CALL_ARGUMENTS))
async def test_write_tools_are_refused_by_default(tool_name, respx_mock):
    """A default-configured server must not write, even if a client asks it to.

    respx_mock intercepts the whole transport, so `call_count == 0` is a real
    claim: the gate has to refuse before `FossaClient` builds a request, not
    merely fail somewhere downstream of one.
    """
    assert server_settings.fossa_allow_writes is False

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(tool_name, WRITE_TOOL_CALL_ARGUMENTS[tool_name])

    assert result.isError is True
    assert respx_mock.calls.call_count == 0
    # Distinguishes a refusal by the write gate from an argument that merely
    # failed validation, which would also be an error with no HTTP traffic.
    assert "FOSSA_ALLOW_WRITES" in _error_text(result), _error_text(result)


@pytest.mark.asyncio
async def test_policy_evaluation_survives_mcp_structured_output(respx_mock):
    """The verdict model nests three levels deep; check it serializes over the wire."""
    project = "git+github.com/acme/widget"
    encoded_project = "git%2Bgithub.com%2Facme%2Fwidget"
    encoded_revision = f"{encoded_project}%24abc123"

    respx_mock.get(f"https://app.fossa.com/api/projects/{encoded_project}").mock(
        return_value=httpx.Response(200, json={"securityIssueScanningEnabled": True})
    )
    respx_mock.get(f"https://app.fossa.com/api/v2/revisions/{encoded_revision}/dependencies").mock(
        return_value=httpx.Response(
            200,
            json={
                "dependencies": [
                    {
                        "locator": "pip+mcp$1.6.0",
                        "title": "mcp",
                        "depth": 1,
                        "issues": [
                            {
                                "type": "vulnerability",
                                "status": "active",
                                "vulnId": "CVE-2025-53365_pip+mcp",
                                "cvssScore": 8.7,
                            }
                        ],
                    }
                ]
            },
        )
    )

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(
            "fossa_evaluate_security_policy",
            {"project_locator": project, "revision_locator": "abc123"},
        )

    assert result.isError is not True
    assert result.structuredContent is not None
    assert result.structuredContent["verdict"] == "block"
    blocked = result.structuredContent["blocked"][0]
    assert blocked["locator"] == "pip+mcp$1.6.0"
    assert blocked["violations"][0]["vuln_id"] == "CVE-2025-53365"


@pytest.mark.asyncio
async def test_mocked_tool_call_returns_structured_output(respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": [{"id": 1, "title": "demo"}]})
    )

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("fossa_list_projects", {"count": 5})

    assert result.isError is not True
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is True
    assert result.structuredContent["data"]["projects"][0]["title"] == "demo"


@pytest.mark.asyncio
async def test_invalid_enum_input_rejected_before_any_http_request(respx_mock):
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("fossa_list_projects", {"types": ["not-a-real-type"]})

    assert result.isError is True
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_business_rule_violation_rejected_before_any_http_request(respx_mock):
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(
            "fossa_list_issues",
            {"category": "licensing", "scope_type": "global", "project_locator": "p"},
        )

    assert result.isError is True
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unexpected_argument_rejected_before_any_http_request(respx_mock):
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(
            "fossa_list_projects", {"count": 5, "not_a_real_argument": "x"}
        )

    # An ignored unknown argument would let a model believe it applied a filter
    # that never reached FOSSA, so the call must fail instead.
    assert result.isError is True
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_tool_schemas_forbid_additional_properties():
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.list_tools()

    for tool in result.tools:
        assert tool.inputSchema.get("additionalProperties") is False, tool.name


@pytest.mark.asyncio
async def test_token_absent_from_tool_output_and_logs(monkeypatch, respx_mock, caplog):
    # Patch the settings object the lifespan builds its client from, so the
    # token really does reach the Authorization header for this call.
    monkeypatch.setattr(server_settings, "fossa_api_token", "leaky-token-value")
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(401, json={"message": "Invalid token", "name": "Unauthorized"})
    )

    with caplog.at_level(logging.DEBUG):
        async with create_connected_server_and_client_session(mcp) as session:
            result = await session.call_tool("fossa_list_projects", {})

    assert route.calls.last.request.headers["Authorization"] == "Bearer leaky-token-value"
    assert result.isError is True
    assert "leaky-token-value" not in result.model_dump_json()
    assert "leaky-token-value" not in caplog.text


@pytest.mark.asyncio
async def test_fossa_error_surfaces_as_mcp_tool_error(respx_mock):
    respx_mock.get("https://app.fossa.com/api/projects/missing").mock(
        return_value=httpx.Response(
            404, json={"message": "Project not found", "name": "NotFoundError"}
        )
    )

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("fossa_get_project", {"project_locator": "missing"})

    assert result.isError is True
    first_block = result.content[0] if result.content else None
    text = first_block.text if isinstance(first_block, TextContent) else ""
    assert "404" in text or "NotFoundError" in text or "not found" in text.lower()
