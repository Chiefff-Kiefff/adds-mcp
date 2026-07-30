"""FastMCP server entrypoint for the ADCS MCP."""

from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

from adds_mcp.client import ReadOnlyADClient

from .config import adcs_settings, adds_settings
from .ldap_source import ADCSLdapClient
from .tools import register_all
from .winrm_source import ReadOnlyWinRMClient


def build_server() -> FastMCP:
    logging.basicConfig(
        level=os.environ.get("ADCS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mcp = FastMCP(
        name="adcs-mcp",
        instructions=(
            "Read-only Active Directory Certificate Services (ADCS) MCP server. "
            "Use the AD-side tools (CAs, templates, trust anchors) for any question "
            "about what is published to the domain; use the WinRM-backed tools "
            "(issued/pending/revoked, ca configuration, role holders) to inspect the "
            "certificate database and settings on online issuing CAs. Offline root "
            "and policy CAs are not queried directly — use parse_certificate_pem to "
            "decode certs or CRLs exported from them."
        ),
        host=adcs_settings.http_host,
        port=adcs_settings.http_port,
    )
    ldap = ADCSLdapClient(ReadOnlyADClient(adds_settings))
    winrm = ReadOnlyWinRMClient(adcs_settings)
    register_all(mcp, ldap, winrm)
    return mcp


def main() -> None:
    transport = os.environ.get("ADCS_TRANSPORT", "streamable-http")
    mcp = build_server()
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
