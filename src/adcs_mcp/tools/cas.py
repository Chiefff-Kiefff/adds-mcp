"""Certification Authority listings from the AD Public Key Services subtree."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from adds_mcp.client import escape_filter

from ..ldap_source import ADCSLdapClient, sub_container
from ._common import CA_ATTRS


def register(mcp: FastMCP, ldap: ADCSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_enrollment_services(
        limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        """List Enterprise Enrollment Services (one entry per Enterprise CA)."""
        results = ldap.search(
            search_filter="(objectClass=pKIEnrollmentService)",
            base_dn=sub_container("Enrollment Services"),
            attributes=CA_ATTRS,
            limit=limit,
        )
        return {"count": len(results), "enrollment_services": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_enrollment_service(
        name: Annotated[str, Field(description="CA name (cn / displayName / dNSHostName / DN).")],
    ) -> dict[str, Any]:
        """Return the full attribute set of a single Enterprise CA."""
        ident = escape_filter(name)
        results = ldap.search(
            search_filter=(
                "(&(objectClass=pKIEnrollmentService)"
                f"(|(cn={ident})(displayName={ident})(dNSHostName={ident})(distinguishedName={ident})))"
            ),
            base_dn=sub_container("Enrollment Services"),
            attributes=CA_ATTRS,
            limit=2,
        )
        if not results:
            return {"found": False, "name": name}
        if len(results) > 1:
            return {"found": True, "ambiguous": True, "matches": results}
        return {"found": True, "enrollment_service": results[0]}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_root_cas() -> dict[str, Any]:
        """List root CAs whose certificates are published in AD (trust anchors)."""
        results = ldap.search(
            search_filter="(objectClass=certificationAuthority)",
            base_dn=sub_container("Certification Authorities"),
            attributes=CA_ATTRS,
            limit=200,
        )
        return {"count": len(results), "root_cas": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_ntauth_cas() -> dict[str, Any]:
        """Return the NTAuthCertificates entry (CAs trusted for AD authentication)."""
        obj = ldap.read(
            sub_container("NTAuthCertificates"),
            attributes=["cACertificate", "distinguishedName", "whenChanged"],
        )
        return {"ntauth": obj}
