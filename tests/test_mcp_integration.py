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
}

# The subset that must advertise destructiveHint=True: deletes, plus the one
# tool whose target set can be a filter rather than an explicit list. A client
# may reasonably turn this hint into a confirmation prompt, so it is pinned
# rather than left to whichever annotation constant a registration picked up.
EXPECTED_DESTRUCTIVE_TOOL_NAMES = {
    "fossa_delete_project_attribution_slug",
    "fossa_delete_project",
    "fossa_delete_projects",
    "fossa_delete_issue_exceptions",
    "fossa_delete_issue_filter",
    "fossa_delete_release_group",
    "fossa_delete_release_group_release",
    "fossa_update_issues",
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
