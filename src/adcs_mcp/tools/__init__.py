"""MCP tool registrations for the ADCS server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..ldap_source import ADCSLdapClient
from ..winrm_source import ReadOnlyWinRMClient
from . import admin, cas, issued, parsing, templates, trust


def register_all(
    mcp: FastMCP,
    ldap: ADCSLdapClient,
    winrm: ReadOnlyWinRMClient,
) -> None:
    cas.register(mcp, ldap)
    templates.register(mcp, ldap)
    trust.register(mcp, ldap)
    issued.register(mcp, winrm)
    admin.register(mcp, winrm)
    parsing.register(mcp)
