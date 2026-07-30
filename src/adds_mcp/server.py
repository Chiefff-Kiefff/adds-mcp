"""FastMCP server entrypoint for the Active Directory MCP."""

from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

from .client import ReadOnlyADClient
from .config import settings
from .tools import register_all


def build_server() -> FastMCP:
    logging.basicConfig(
        level=os.environ.get("ADDS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mcp = FastMCP(
        name="adds-mcp",
        instructions=(
            "Read-only Active Directory MCP server. Use these tools to query users, "
            "groups, OUs, computers, GPOs, and domain metadata for monitoring and "
            "investigation. Every tool is read-only; no directory modifications are "
            "possible. Prefer the type-specific search_/get_ tools; fall back to "
            "ldap_search for advanced filters."
        ),
        host=settings.http_host,
        port=settings.http_port,
    )
    client = ReadOnlyADClient(settings)
    register_all(mcp, client)
    return mcp


def main() -> None:
    """CLI entrypoint. Defaults to streamable-http transport."""
    transport = os.environ.get("ADDS_TRANSPORT", "streamable-http")
    mcp = build_server()
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
