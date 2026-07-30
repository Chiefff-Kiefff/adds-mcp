"""LDAP source for AD-integrated DNS.

AD stores DNS zones and records in two partitions:
  DC=DomainDnsZones,DC=<domain>...   (domain-scoped)
  DC=ForestDnsZones,DC=<forest-root> (forest-scoped)

The legacy location (System container) is also supported for zones not moved
to application partitions.
"""

from __future__ import annotations

from typing import Any, Iterable

from adds_mcp.client import ReadOnlyADClient

from .config import adds_settings


def _base_from_dc(base_dn: str, prefix: str) -> str:
    return f"{prefix},{base_dn}"


def dns_partition_dns() -> list[str]:
    """Return likely DNS partition DNs (domain + forest + legacy)."""
    if not adds_settings.base_dn:
        raise RuntimeError("ADDS_BASE_DN is not set.")
    return [
        _base_from_dc(adds_settings.base_dn, "DC=DomainDnsZones"),
        _base_from_dc(adds_settings.base_dn, "DC=ForestDnsZones"),
        _base_from_dc(adds_settings.base_dn, "CN=MicrosoftDNS,CN=System"),
    ]


class ADDNSLdapClient:
    """Thin wrapper: search across all likely DNS partitions."""

    def __init__(self, ldap: ReadOnlyADClient) -> None:
        self._ldap = ldap

    def search_all_partitions(
        self,
        *,
        search_filter: str,
        attributes: Iterable[str] | str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_dns: set[str] = set()
        for base in dns_partition_dns():
            try:
                partial = self._ldap.search(
                    search_filter=search_filter,
                    base_dn=base,
                    scope="subtree",
                    attributes=attributes,
                    size_limit=limit,
                    page_size=min(limit, 200),
                )
            except RuntimeError:
                # Partition may not exist (e.g. no ForestDnsZones on a child domain).
                continue
            for entry in partial:
                dn = entry.get("dn")
                if dn and dn not in seen_dns:
                    seen_dns.add(dn)
                    results.append(entry)
            if len(results) >= limit:
                break
        return results[:limit]

    def search_zone(
        self,
        zone_dn: str,
        *,
        search_filter: str,
        attributes: Iterable[str] | str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return self._ldap.search(
            search_filter=search_filter,
            base_dn=zone_dn,
            scope="subtree",
            attributes=attributes,
            size_limit=limit,
            page_size=min(limit, 200),
        )

    def read(self, dn: str, attributes: Iterable[str] | str | None = None) -> dict[str, Any] | None:
        return self._ldap.read_object(dn, attributes=attributes)
