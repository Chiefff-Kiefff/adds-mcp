"""LDAP source for ADCS AD-published objects.

All Enterprise CA metadata (CAs, templates, enrollment services, AIA/CDP/KRA)
lives under CN=Public Key Services,CN=Services,CN=Configuration,DC=...
We reuse adds_mcp's read-only LDAP client and just point it at that subtree.
"""

from __future__ import annotations

from typing import Any, Iterable

from adds_mcp.client import ReadOnlyADClient

from .config import adds_settings


def pki_base_dn() -> str:
    """Return the DN of the AD Public Key Services container."""
    if not adds_settings.base_dn:
        raise RuntimeError(
            "ADDS_BASE_DN is not set; the ADCS server needs it to locate "
            "CN=Public Key Services,CN=Services,CN=Configuration,<base_dn>."
        )
    # Configuration NC has the same suffix as the domain NC in a single-domain forest.
    return f"CN=Public Key Services,CN=Services,CN=Configuration,{adds_settings.base_dn}"


def sub_container(name: str) -> str:
    return f"CN={name},{pki_base_dn()}"


class ADCSLdapClient:
    """Wraps a ReadOnlyADClient for PKI subtree queries."""

    def __init__(self, ldap: ReadOnlyADClient) -> None:
        self._ldap = ldap

    def search(
        self,
        *,
        search_filter: str,
        base_dn: str | None = None,
        scope: str = "subtree",
        attributes: Iterable[str] | str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return self._ldap.search(
            search_filter=search_filter,
            base_dn=base_dn or pki_base_dn(),
            scope=scope,
            attributes=attributes,
            size_limit=limit,
            page_size=min(limit, 200),
        )

    def read(self, dn: str, attributes: Iterable[str] | str | None = None) -> dict[str, Any] | None:
        return self._ldap.read_object(dn, attributes=attributes)
