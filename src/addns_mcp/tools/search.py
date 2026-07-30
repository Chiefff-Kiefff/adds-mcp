"""Cross-zone DNS search utilities."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from adds_mcp.client import escape_filter

from ..ldap_source import ADDNSLdapClient
from ..records import decode_records


def _decode(node: dict[str, Any]) -> list[dict[str, Any]]:
    raw = node.get("attributes", {}).get("dnsRecord")
    if raw is None:
        return []
    blobs = raw if isinstance(raw, list) else [raw]
    byte_blobs = [b.encode("latin-1") if isinstance(b, str) else b for b in blobs]
    return decode_records(byte_blobs)


def _ip_to_reverse_zone(ip_str: str) -> str | None:
    """Convert an IPv4/IPv6 address to its expected reverse zone label sequence."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    return addr.reverse_pointer  # e.g. "5.4.3.2.in-addr.arpa"


def register(mcp: FastMCP, ldap: ADDNSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def search_by_name(
        name: Annotated[
            str,
            Field(description="Label to search for across every zone (substring match on dc=)."),
        ],
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """Find every dnsNode across all zones whose label matches (substring)."""
        q = escape_filter(name)
        nodes = ldap.search_all_partitions(
            search_filter=f"(&(objectClass=dnsNode)(dc=*{q}*))",
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=limit,
        )
        out: list[dict[str, Any]] = []
        for node in nodes:
            out.append(
                {
                    "name": node.get("attributes", {}).get("dc"),
                    "dn": node["dn"],
                    "records": _decode(node),
                }
            )
        return {"query": name, "count": len(out), "matches": out}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def search_by_ip(
        ip: Annotated[str, Field(description="IPv4 or IPv6 address to find in A/AAAA/PTR records.")],
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """Find every DNS record referencing a given IP.

        Scans forward zones for A/AAAA payloads matching ``ip``, and the reverse
        PTR node if one exists. Returns both together.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": f"Invalid IP address: {ip}"}

        # 1. Forward: pull A (or AAAA) nodes and match on decoded value.
        rr_filter = "(&(objectClass=dnsNode))"  # payload isn't LDAP-indexable
        nodes = ldap.search_all_partitions(
            search_filter=rr_filter,
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=limit * 4,
        )
        target = str(addr)
        target_type = "A" if isinstance(addr, ipaddress.IPv4Address) else "AAAA"
        forward_hits: list[dict[str, Any]] = []
        for node in nodes:
            recs = _decode(node)
            matches = [r for r in recs if r["type"] == target_type and r["value"] == target]
            if matches:
                forward_hits.append(
                    {
                        "name": node.get("attributes", {}).get("dc"),
                        "dn": node["dn"],
                        "records": matches,
                    }
                )
            if len(forward_hits) >= limit:
                break

        # 2. Reverse: use the reverse-pointer label.
        reverse_hits: list[dict[str, Any]] = []
        rev_full = _ip_to_reverse_zone(ip) or ""
        # rev_full is like "5.4.3.2.in-addr.arpa"; the first label is the record name,
        # remaining labels form the zone name.
        parts = rev_full.split(".")
        if len(parts) >= 3 and (parts[-1] == "arpa"):
            # Try progressively shorter zones (e.g. /24 vs /16 reverse zones).
            for split_at in range(1, len(parts) - 2):
                label = ".".join(parts[:split_at])
                zone = ".".join(parts[split_at:])
                zone_dn_matches = ldap.search_all_partitions(
                    search_filter=(
                        f"(&(objectClass=dnsZone)(dc={escape_filter(zone)}))"
                    ),
                    attributes=["distinguishedName"],
                    limit=1,
                )
                if not zone_dn_matches:
                    continue
                nodes = ldap.search_zone(
                    zone_dn=zone_dn_matches[0]["dn"],
                    search_filter=f"(&(objectClass=dnsNode)(dc={escape_filter(label)}))",
                    attributes=["dc", "distinguishedName", "dnsRecord"],
                    limit=5,
                )
                for node in nodes:
                    recs = _decode(node)
                    ptr = [r for r in recs if r["type"] == "PTR"]
                    if ptr:
                        reverse_hits.append(
                            {
                                "reverse_zone": zone,
                                "label": label,
                                "dn": node["dn"],
                                "records": ptr,
                            }
                        )

        return {
            "ip": ip,
            "forward_count": len(forward_hits),
            "forward_matches": forward_hits,
            "reverse_count": len(reverse_hits),
            "reverse_matches": reverse_hits,
        }
