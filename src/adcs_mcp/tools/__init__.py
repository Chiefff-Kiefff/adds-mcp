"""MCP tool registrations for the ADCS server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..http_source import PkiWebClient
from ..ldap_source import ADCSLdapClient
from ..winrm_source import ReadOnlyWinRMClient
from . import admin, cas, issued, parsing, templates, trust, web


def register_all(
    mcp: FastMCP,
    ldap: ADCSLdapClient,
    winrm: ReadOnlyWinRMClient,
    web_client: PkiWebClient,
) -> None:
    cas.register(mcp, ldap)
    templates.register(mcp, ldap)
    trust.register(mcp, ldap)
    issued.register(mcp, winrm)
    admin.register(mcp, winrm)
    web.register(mcp, web_client)
    parsing.register(mcp)
