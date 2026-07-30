"""Main entry point for the FOSSA MCP server."""

import asyncio
import sys
from fossa_mcp.server import main

if __name__ == "__main__":
    # Run the main function with the command line arguments
    asyncio.run(main(sys.argv[1:]))