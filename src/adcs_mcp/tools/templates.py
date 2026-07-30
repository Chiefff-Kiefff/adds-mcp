"""Certificate template tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from adds_mcp.client import escape_filter

from ..ldap_source import ADCSLdapClient, sub_container
from ._common import (
    ENROLLMENT_FLAG_BITS,
    NAME_FLAG_BITS,
    PRIVATE_KEY_FLAG_BITS,
    TEMPLATE_ATTRS,
    decode_bit_flags,
)


def _decode_template_flags(template: dict[str, Any]) -> None:
    attrs = template.get("attributes", {})
    if "msPKI-Certificate-Name-Flag" in attrs:
        attrs["msPKI-Certificate-Name-Flag_decoded"] = decode_bit_flags(
            attrs["msPKI-Certificate-Name-Flag"], NAME_FLAG_BITS
        )
    if "msPKI-Enrollment-Flag" in attrs:
        attrs["msPKI-Enrollment-Flag_decoded"] = decode_bit_flags(
            attrs["msPKI-Enrollment-Flag"], ENROLLMENT_FLAG_BITS
        )
    if "msPKI-Private-Key-Flag" in attrs:
        attrs["msPKI-Private-Key-Flag_decoded"] = decode_bit_flags(
            attrs["msPKI-Private-Key-Flag"], PRIVATE_KEY_FLAG_BITS
        )


def register(mcp: FastMCP, ldap: ADCSLdapClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_certificate_templates(
        query: Annotated[
            str,
            Field(default="", description="Substring match on displayName / cn."),
        ] = "",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List all certificate templates published in AD."""
        filt = "(objectClass=pKICertificateTemplate)"
        if query:
            q = escape_filter(query)
            filt = f"(&{filt}(|(displayName=*{q}*)(cn=*{q}*)))"
        results = ldap.search(
            search_filter=filt,
            base_dn=sub_container("Certificate Templates"),
            attributes=TEMPLATE_ATTRS,
            limit=limit,
        )
        for t in results:
            _decode_template_flags(t)
        return {"count": len(results), "templates": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_certificate_template(
        identifier: Annotated[
            str,
            Field(description="Template displayName, cn, OID (msPKI-Cert-Template-OID), or DN."),
        ],
    ) -> dict[str, Any]:
        """Return the full attribute set for a certificate template."""
        ident = escape_filter(identifier)
        filt = (
            "(&(objectClass=pKICertificateTemplate)"
            f"(|(displayName={ident})(cn={ident})(msPKI-Cert-Template-OID={ident})(distinguishedName={ident})))"
        )
        results = ldap.search(
            search_filter=filt,
            base_dn=sub_container("Certificate Templates"),
            attributes=TEMPLATE_ATTRS,
            limit=2,
        )
        if not results:
            return {"found": False, "identifier": identifier}
        if len(results) > 1:
            return {"found": True, "ambiguous": True, "matches": results}
        _decode_template_flags(results[0])
        return {"found": True, "template": results[0]}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_templates_by_eku(
        eku_oid: Annotated[
            str,
            Field(
                description=(
                    "EKU OID to filter templates by. Examples: "
                    "1.3.6.1.5.5.7.3.1 (Server Auth), 1.3.6.1.5.5.7.3.2 (Client Auth), "
                    "1.3.6.1.4.1.311.20.2.2 (Smart Card Logon), "
                    "1.3.6.1.4.1.311.21.6 (Key Recovery Agent)."
                )
            ),
        ],
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List templates that include a given EKU."""
        oid = escape_filter(eku_oid)
        results = ldap.search(
            search_filter=(
                f"(&(objectClass=pKICertificateTemplate)(pKIExtendedKeyUsage={oid}))"
            ),
            base_dn=sub_container("Certificate Templates"),
            attributes=TEMPLATE_ATTRS,
            limit=limit,
        )
        for t in results:
            _decode_template_flags(t)
        return {"eku_oid": eku_oid, "count": len(results), "templates": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def find_templates_offered_by_ca(
        ca_name: Annotated[
            str,
            Field(description="CA name (cn / displayName / dNSHostName)."),
        ],
    ) -> dict[str, Any]:
        """List templates the given Enterprise CA is configured to issue.

        Uses the ``certificateTemplates`` attribute on the CA's pKIEnrollmentService object.
        """
        ident = escape_filter(ca_name)
        ca = ldap.search(
            search_filter=(
                "(&(objectClass=pKIEnrollmentService)"
                f"(|(cn={ident})(displayName={ident})(dNSHostName={ident})))"
            ),
            base_dn=sub_container("Enrollment Services"),
            attributes=["cn", "distinguishedName", "certificateTemplates"],
            limit=2,
        )
        if not ca:
            return {"found": False, "ca_name": ca_name}
        offered = ca[0].get("attributes", {}).get("certificateTemplates") or []
        if isinstance(offered, str):
            offered = [offered]
        return {
            "found": True,
            "ca_dn": ca[0]["dn"],
            "offered_templates": offered,
            "count": len(offered),
        }
