"""Per-zone record listings."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from adds_mcp.client import escape_filter

from ..ldap_source import ADDNSLdapClient
from ..records import DNS_TYPE_NAMES, decode_records


def _find_zone_dn(ldap: ADDNSLdapClient, zone_name: str) -> str | None:
    ident = escape_filter(zone_name)
    matches = ldap.search_all_partitions(
        search_filter=f"(&(objectClass=dnsZone)(dc={ident}))",
        attributes=["distinguishedName"],
        limit=1,
    )
    return matches[0]["dn"] if matches else None


def _decode_node_records(node: dict[str, Any]) -> list[dict[str, Any]]:
    raw = node.get("attributes", {}).get("dnsRecord")
    if raw is None:
        return []
    blobs = raw if isinstance(raw, list) else [raw]
    byte_blobs = [b.encode("latin-1") if isinstance(b, str) else b for b in blobs]
    return decode_records(byte_blobs)


def _flatten(node: dict[str, Any], types_filter: set[str] | None) -> list[dict[str, Any]]:
    label = node.get("attributes", {}).get("dc") or "@"
    records = _decode_node_records(node)
    if types_filter:
        records = [r for r in records if r["type"] in types_filter]
    return [
        {"name": label, "dn": node["dn"], **r}
        for r in records
    ]


def register(mcp: FastMCP, ldap: ADDNSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_records(
        zone_name: Annotated[str, Field(description="Zone name, e.g. 'corp.example.com'.")],
        record_types: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    "Filter to specific RR types (e.g. ['A','AAAA','CNAME']). "
                    "Omit for all types."
                ),
            ),
        ] = None,
        name_prefix: Annotated[
            str,
            Field(default="", description="Optional case-sensitive label prefix filter (dc=*prefix*)."),
        ] = "",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List all records in a zone (optionally filtered by type / name prefix)."""
        zone_dn = _find_zone_dn(ldap, zone_name)
        if not zone_dn:
            return {"found": False, "zone_name": zone_name}
        node_filter = "(objectClass=dnsNode)"
        if name_prefix:
            node_filter = f"(&(objectClass=dnsNode)(dc=*{escape_filter(name_prefix)}*))"
        nodes = ldap.search_zone(
            zone_dn=zone_dn,
            search_filter=node_filter,
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=limit * 4,
        )
        types_set: set[str] | None
        if record_types:
            types_set = {t.upper() for t in record_types}
            valid = set(DNS_TYPE_NAMES.values())
            invalid = types_set - valid
            if invalid:
                return {"error": f"Unknown record types: {sorted(invalid)}"}
        else:
            types_set = None
        flat: list[dict[str, Any]] = []
        for node in nodes:
            flat.extend(_flatten(node, types_set))
            if len(flat) >= limit:
                break
        return {
            "zone_name": zone_name,
            "zone_dn": zone_dn,
            "count": len(flat[:limit]),
            "records": flat[:limit],
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_record(
        zone_name: Annotated[str, Field(description="Zone name.")],
        name: Annotated[
            str,
            Field(description="Record label, e.g. 'www' or '@' for the zone apex."),
        ],
    ) -> dict[str, Any]:
        """Fetch every record for a single node (all types) in a zone."""
        zone_dn = _find_zone_dn(ldap, zone_name)
        if not zone_dn:
            return {"found": False, "zone_name": zone_name}
        ident = escape_filter(name)
        nodes = ldap.search_zone(
            zone_dn=zone_dn,
            search_filter=f"(&(objectClass=dnsNode)(dc={ident}))",
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=1,
        )
        if not nodes:
            return {"found": False, "zone_name": zone_name, "name": name}
        records = _decode_node_records(nodes[0])
        return {
            "found": True,
            "zone_name": zone_name,
            "name": name,
            "dn": nodes[0]["dn"],
            "records": records,
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_stale_records(
        zone_name: Annotated[str, Field(description="Zone name.")],
        older_than_days: Annotated[
            int,
            Field(default=30, ge=1, le=3650, description="Aging timestamp older than N days."),
        ] = 30,
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List dynamic (non-static) records with aging timestamps older than N days."""
        from datetime import datetime, timedelta, timezone

        zone_dn = _find_zone_dn(ldap, zone_name)
        if not zone_dn:
            return {"found": False, "zone_name": zone_name}
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        nodes = ldap.search_zone(
            zone_dn=zone_dn,
            search_filter="(objectClass=dnsNode)",
            attributes=["dc", "distinguishedName", "dnsRecord"],
            limit=limit * 4,
        )
        stale: list[dict[str, Any]] = []
        for node in nodes:
            label = node.get("attributes", {}).get("dc") or "@"
            for r in _decode_node_records(node):
                if r["static"] or not r["aging_timestamp"]:
                    continue
                try:
                    ts = datetime.fromisoformat(r["aging_timestamp"])
                except ValueError:
                    continue
                if ts < cutoff:
                    stale.append({"name": label, "dn": node["dn"], **r})
                if len(stale) >= limit:
                    break
            if len(stale) >= limit:
                break
        return {
            "zone_name": zone_name,
            "older_than_days": older_than_days,
            "count": len(stale),
            "records": stale,
        }
