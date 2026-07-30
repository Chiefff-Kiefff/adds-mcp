"""DNS zone-level tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from adds_mcp.client import escape_filter

from ..ldap_source import ADDNSLdapClient
from ..records import decode_records

ZONE_ATTRS = [
    "dc",
    "distinguishedName",
    "name",
    "dNSProperty",
    "objectClass",
    "whenCreated",
    "whenChanged",
]


def _zone_name_from_dn(dn: str) -> str:
    # First DC= component is the zone name.
    for part in dn.split(","):
        if part.lower().startswith("dc="):
            return part.split("=", 1)[1]
    return dn


def register(mcp: FastMCP, ldap: ADDNSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_zones(
        query: Annotated[
            str,
            Field(default="", description="Substring match on the zone name."),
        ] = "",
        include_reverse: Annotated[
            bool,
            Field(default=True, description="Include reverse lookup (in-addr.arpa/ip6.arpa) zones."),
        ] = True,
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List all AD-integrated DNS zones across domain, forest, and legacy containers."""
        filt = "(objectClass=dnsZone)"
        if query:
            q = escape_filter(query)
            filt = f"(&{filt}(dc=*{q}*))"
        results = ldap.search_all_partitions(
            search_filter=filt, attributes=ZONE_ATTRS, limit=limit
        )
        summarized: list[dict[str, Any]] = []
        for zone in results:
            name = _zone_name_from_dn(zone["dn"])
            is_reverse = name.endswith("in-addr.arpa") or name.endswith("ip6.arpa")
            if not include_reverse and is_reverse:
                continue
            summarized.append(
                {
                    "name": name,
                    "dn": zone["dn"],
                    "type": "reverse" if is_reverse else "forward",
                }
            )
        return {"count": len(summarized), "zones": summarized}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_zone(
        zone_name: Annotated[
            str,
            Field(description="Zone name, e.g. 'corp.example.com' or '10.in-addr.arpa'."),
        ],
    ) -> dict[str, Any]:
        """Return zone metadata plus its SOA + NS records."""
        ident = escape_filter(zone_name)
        results = ldap.search_all_partitions(
            search_filter=f"(&(objectClass=dnsZone)(dc={ident}))",
            attributes=ZONE_ATTRS,
            limit=2,
        )
        if not results:
            return {"found": False, "zone_name": zone_name}
        zone = results[0]
        # Fetch the '@' apex node which holds SOA + NS.
        apex = ldap.search_zone(
            zone_dn=zone["dn"],
            search_filter="(&(objectClass=dnsNode)(dc=@))",
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=1,
        )
        apex_records: list[dict[str, Any]] = []
        if apex:
            raw = apex[0].get("attributes", {}).get("dnsRecord")
            blobs = raw if isinstance(raw, list) else ([raw] if raw else [])
            # ldap3 decoded blobs may come back as strings — undo utf-8 heuristic.
            byte_blobs = [b.encode("latin-1") if isinstance(b, str) else b for b in blobs]
            apex_records = decode_records(byte_blobs)
        return {
            "found": True,
            "zone_name": zone_name,
            "zone": zone,
            "apex_records": apex_records,
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_conditional_forwarders(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List conditional forwarder zones (zones configured as Forwarder type in AD-integrated DNS)."""
        # Conditional forwarders have objectClass=dnsZone with a "Forwarders" dnsProperty.
        results = ldap.search_all_partitions(
            search_filter="(&(objectClass=dnsZone)(dnsProperty=*))",
            attributes=ZONE_ATTRS,
            limit=limit,
        )
        return {"count": len(results), "zones": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_zone_delegations(
        zone_name: Annotated[str, Field(description="Parent zone name.")],
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List NS-delegated subzones under a parent zone."""
        ident = escape_filter(zone_name)
        zone_matches = ldap.search_all_partitions(
            search_filter=f"(&(objectClass=dnsZone)(dc={ident}))",
            attributes=["distinguishedName"],
            limit=1,
        )
        if not zone_matches:
            return {"found": False, "zone_name": zone_name}
        # A dnsNode with NS records but not at the apex is a delegation point.
        nodes = ldap.search_zone(
            zone_dn=zone_matches[0]["dn"],
            search_filter="(&(objectClass=dnsNode)(!(dc=@)))",
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=limit * 4,
        )
        delegations: list[dict[str, Any]] = []
        for node in nodes:
            raw = node.get("attributes", {}).get("dnsRecord")
            blobs = raw if isinstance(raw, list) else ([raw] if raw else [])
            byte_blobs = [b.encode("latin-1") if isinstance(b, str) else b for b in blobs]
            recs = decode_records(byte_blobs)
            ns_records = [r for r in recs if r["type"] == "NS"]
            if ns_records:
                delegations.append(
                    {
                        "dn": node["dn"],
                        "label": node.get("attributes", {}).get("dc"),
                        "ns_records": ns_records,
                    }
                )
            if len(delegations) >= limit:
                break
        return {"zone_name": zone_name, "count": len(delegations), "delegations": delegations}
