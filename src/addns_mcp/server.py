"""FastMCP server entrypoint for the AD DNS MCP."""

from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

from adds_mcp.client import ReadOnlyADClient

from .config import adds_settings, addns_settings
from .ldap_source import ADDNSLdapClient
from .tools import register_all


def build_server() -> FastMCP:
    logging.basicConfig(
        level=os.environ.get("ADDNS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mcp = FastMCP(
        name="addns-mcp",
        instructions=(
            "Read-only Active Directory-integrated DNS MCP server. Use these tools "
            "to inspect DNS zones and records stored in AD's DomainDnsZones and "
            "ForestDnsZones partitions. All record blobs are decoded (A, AAAA, "
            "CNAME, NS, PTR, MX, SRV, TXT, SOA). Nothing is mutable."
        ),
        host=addns_settings.http_host,
        port=addns_settings.http_port,
    )
    ldap = ADDNSLdapClient(ReadOnlyADClient(adds_settings))
    register_all(mcp, ldap)
    return mcp


def main() -> None:
    transport = os.environ.get("ADDNS_TRANSPORT", "streamable-http")
    mcp = build_server()
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
