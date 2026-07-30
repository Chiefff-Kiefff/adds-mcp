"""MCP tool registrations, grouped by AD object type."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ReadOnlyADClient
from . import computers, domain, gpos, groups, ous, search, users


def register_all(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    users.register(mcp, client)
    groups.register(mcp, client)
    ous.register(mcp, client)
    computers.register(mcp, client)
    gpos.register(mcp, client)
    domain.register(mcp, client)
    search.register(mcp, client)
