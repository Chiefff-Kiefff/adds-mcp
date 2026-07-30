"""AIA / CDP / KRA / OID container listings."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..ldap_source import ADCSLdapClient, sub_container
from ._common import TRUST_ANCHOR_ATTRS


def register(mcp: FastMCP, ldap: ADCSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_aia_entries() -> dict[str, Any]:
        """List Authority Information Access entries published in AD (CN=AIA)."""
        results = ldap.search(
            search_filter="(objectClass=certificationAuthority)",
            base_dn=sub_container("AIA"),
            attributes=TRUST_ANCHOR_ATTRS,
            limit=200,
        )
        return {"count": len(results), "aia": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_cdp_entries() -> dict[str, Any]:
        """List CRL Distribution Point entries and their published CRLs (CN=CDP)."""
        results = ldap.search(
            search_filter="(|(objectClass=cRLDistributionPoint)(objectClass=container))",
            base_dn=sub_container("CDP"),
            attributes=[
                "cn",
                "distinguishedName",
                "certificateRevocationList",
                "authorityRevocationList",
                "deltaRevocationList",
                "whenChanged",
            ],
            limit=500,
        )
        return {"count": len(results), "cdp": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_kra_certificates() -> dict[str, Any]:
        """List Key Recovery Agent certificates published in AD (CN=KRA)."""
        results = ldap.search(
            search_filter="(objectClass=msPKI-PrivateKeyRecoveryAgent)",
            base_dn=sub_container("KRA"),
            attributes=TRUST_ANCHOR_ATTRS + ["userCertificate"],
            limit=200,
        )
        return {"count": len(results), "kra": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_pki_oids() -> dict[str, Any]:
        """List custom OIDs registered by the domain (CN=OID)."""
        results = ldap.search(
            search_filter="(objectClass=msPKI-Enterprise-Oid)",
            base_dn=sub_container("OID"),
            attributes=[
                "cn",
                "distinguishedName",
                "displayName",
                "msPKI-Cert-Template-OID",
                "msPKI-OID-Attribute",
                "msPKI-OID-CPS",
                "whenChanged",
            ],
            limit=500,
        )
        return {"count": len(results), "oids": results}
