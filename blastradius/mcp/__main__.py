"""python -m blastradius.mcp — start the MCP server on stdio."""

from blastradius.mcp.server import main

if __name__ == "__main__":
    raise SystemExit(main())
