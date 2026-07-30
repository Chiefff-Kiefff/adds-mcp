"""DNS MCP tool registrations."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..ldap_source import ADDNSLdapClient
from . import records, search, zones


def register_all(mcp: FastMCP, ldap: ADDNSLdapClient) -> None:
    zones.register(mcp, ldap)
    records.register(mcp, ldap)
    search.register(mcp, ldap)
