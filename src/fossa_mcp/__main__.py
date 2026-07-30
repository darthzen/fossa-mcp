"""Main entry point for the FOSSA MCP server."""

import sys

from fossa_mcp.server import main

if __name__ == "__main__":
    main(sys.argv[1:])
