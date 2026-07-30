"""FOSSA MCP server implementation."""

import asyncio
import logging
from typing import List, Optional
from mcp.server import MCPServer
from mcp.server.stdio import stdio_server
from mcp.server.http import http_server

from .config import Settings
from .client import FossaClient
from .tools import projects, revisions, dependencies, issues, posture, reports

logger = logging.getLogger(__name__)

# Create the MCP server instance
mcp = MCPServer(
    "FOSSA",
    version="0.1.0",
    instructions=(
        "Read-only access to FOSSA projects, revisions, dependencies, "
        "licensing issues, vulnerability issues, quality issues, and "
        "attribution reports. No tool mutates FOSSA state."
    ),
)

# Register the tools
mcp.tool("fossa_list_projects", projects.list_projects, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_get_project", projects.get_project, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_list_project_revisions", revisions.list_project_revisions, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_list_dependencies", dependencies.list_dependencies, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_get_dependency", dependencies.get_dependency, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_list_issues", issues.list_issues, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_get_issue", issues.get_issue, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_project_posture", posture.project_posture, annotations={"read_only_hint": True, "open_world_hint": True})
mcp.tool("fossa_get_attribution_report", reports.get_attribution_report, annotations={"read_only_hint": True, "open_world_hint": True})


async def main(args: List[str]) -> None:
    """Main entry point for the FOSSA MCP server."""

    # Parse command line arguments
    transport = "stdio"
    if len(args) > 0:
        if args[0] == "--transport":
            if len(args) > 1:
                transport = args[1]
            else:
                raise ValueError("Missing transport value after --transport")
        elif args[0] == "--version":
            print("fossa-mcp version 0.1.0")
            return
        else:
            # Unknown argument
            raise ValueError(f"Unknown argument: {args[0]}")

    # Setup logging
    settings = Settings()
    logging.basicConfig(
        level=getattr(logging, settings.fossa_log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler()  # This will go to stderr by default
        ]
    )

    logger.info(f"Starting FOSSA MCP server with transport: {transport}")

    # Create the FOSSA client
    client = FossaClient(settings)

    # Register the lifespan for the client
    @mcp.lifespan
    async def lifespan():
        """Lifespan context manager for the MCP server."""
        try:
            yield {"client": client}
        finally:
            await client.aclose()

    # Start the appropriate transport
    if transport == "stdio":
        await stdio_server(mcp)
    elif transport == "streamable-http":
        await http_server(mcp, host=settings.fossa_http_host, port=settings.fossa_http_port)
    else:
        raise ValueError(f"Unknown transport: {transport}")