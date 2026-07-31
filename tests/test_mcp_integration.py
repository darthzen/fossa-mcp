"""In-memory MCP protocol integration tests for the FOSSA MCP server.

Uses `mcp.shared.memory.create_connected_server_and_client_session` to drive
the real FastMCP server through an in-memory client session, so tool
registration, JSON schema validation, and MCP-level error surfacing
(`isError=True`) are exercised exactly as a real MCP client would see them.
"""

import logging

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

from fossa_mcp.server import mcp
from fossa_mcp.server import settings as server_settings

EXPECTED_READ_ONLY_TOOL_NAMES = {
    "fossa_list_projects",
    "fossa_get_project",
    "fossa_list_project_revisions",
    "fossa_list_dependencies",
    "fossa_get_dependency",
    "fossa_list_issues",
    "fossa_get_issue",
    "fossa_project_posture",
    "fossa_get_attribution_report",
    "fossa_get_security_policy",
    "fossa_evaluate_security_policy",
}

# The only tools permitted to modify FOSSA state. Adding a name here is a
# deliberate act — see DECISIONS.md §5, which records why the server stopped
# being wholly read-only. A tool that writes must be listed here and must
# advertise readOnlyHint=False, or this test fails.
EXPECTED_WRITE_TOOL_NAMES = {
    "fossa_enable_security_policy",
    "fossa_assign_security_policy_to_projects",
}


@pytest.mark.asyncio
async def test_tools_list_partitions_into_declared_read_and_write_tools():
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.list_tools()

    names = {tool.name for tool in result.tools}
    assert names == EXPECTED_READ_ONLY_TOOL_NAMES | EXPECTED_WRITE_TOOL_NAMES

    for tool in result.tools:
        assert tool.annotations is not None
        expected_read_only = tool.name in EXPECTED_READ_ONLY_TOOL_NAMES
        assert tool.annotations.readOnlyHint is expected_read_only, (
            f"{tool.name} advertises readOnlyHint={tool.annotations.readOnlyHint}"
        )


@pytest.mark.asyncio
async def test_write_tools_are_refused_by_default(respx_mock):
    """A default-configured server must not write, even if a client asks it to."""
    assert server_settings.fossa_allow_writes is False

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(
            "fossa_enable_security_policy",
            {"project_locator": "git+github.com/acme/widget", "security_policy_id": 7},
        )

    assert result.isError is True
    assert respx_mock.calls.call_count == 0


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
