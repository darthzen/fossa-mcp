"""In-memory MCP protocol integration tests for the FOSSA MCP server.

Uses `mcp.shared.memory.create_connected_server_and_client_session` to drive
the real FastMCP server through an in-memory client session, so tool
registration, JSON schema validation, and MCP-level error surfacing
(`isError=True`) are exercised exactly as a real MCP client would see them.
"""

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

from fossa_mcp.server import mcp

EXPECTED_TOOL_NAMES = {
    "fossa_list_projects",
    "fossa_get_project",
    "fossa_list_project_revisions",
    "fossa_list_dependencies",
    "fossa_get_dependency",
    "fossa_list_issues",
    "fossa_get_issue",
    "fossa_project_posture",
    "fossa_get_attribution_report",
}


@pytest.mark.asyncio
async def test_tools_list_returns_exactly_nine_read_only_tools():
    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.list_tools()

    assert len(result.tools) == 9
    assert {tool.name for tool in result.tools} == EXPECTED_TOOL_NAMES
    for tool in result.tools:
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True


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
