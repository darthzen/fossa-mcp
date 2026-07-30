"""Integration tests for FOSSA MCP server."""

import sys
import os

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp.server import MCPServer
from fossa_mcp.server import mcp


def test_server_creation():
    """Test that the MCP server is properly created."""
    assert isinstance(mcp, MCPServer)
    assert mcp.name == "FOSSA"


def test_tool_registration():
    """Test that all required tools are registered."""
    # Get list of tools
    tools = [tool for tool in mcp.tools]

    # Check we have exactly 9 tools
    assert len(tools) == 9

    # Check tool names match specification
    tool_names = {tool.name for tool in tools}
    expected_tools = {
        "fossa_list_projects",
        "fossa_get_project",
        "fossa_list_project_revisions",
        "fossa_list_dependencies",
        "fossa_get_dependency",
        "fossa_list_issues",
        "fossa_get_issue",
        "fossa_project_posture",
        "fossa_get_attribution_report"
    }

    assert tool_names == expected_tools