"""Domain-wide metadata: password policy, FSMO roles, trusts, sites."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient
from ..config import settings
from ..formatting import TRUST_DIRECTION, TRUST_TYPE
from ._common import DOMAIN_ATTRS, TRUST_ATTRS

# FSMO roles are stored as fSMORoleOwner attribute on specific containers.
_FSMO_LOCATIONS = {
    "SchemaMaster": "CN=Schema,CN=Configuration,{base}",
    "DomainNamingMaster": "CN=Partitions,CN=Configuration,{base}",
    "PDCEmulator": "{base}",
    "RIDMaster": "CN=RID Manager$,CN=System,{base}",
    "InfrastructureMaster": "CN=Infrastructure,{base}",
}


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_domain_info() -> dict[str, Any]:
        """Return domain root attributes plus rootDSE server info."""
        obj = client.read_object(settings.base_dn, attributes=DOMAIN_ATTRS)
        return {
            "base_dn": settings.base_dn,
            "domain": settings.domain,
            "server_info": client.domain_info(),
            "domain_object": obj,
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_password_policy() -> dict[str, Any]:
        """Return the default domain password / lockout policy."""
        obj = client.read_object(
            settings.base_dn,
            attributes=[
                "maxPwdAge",
                "minPwdAge",
                "minPwdLength",
                "pwdHistoryLength",
                "pwdProperties",
                "lockoutDuration",
                "lockoutObservationWindow",
                "lockoutThreshold",
            ],
        )
        return {"base_dn": settings.base_dn, "policy": obj}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_fine_grained_password_policies(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List Fine-Grained Password Policies (PSOs) defined in the Password Settings Container."""
        base = f"CN=Password Settings Container,CN=System,{settings.base_dn}"
        results = client.search(
            search_filter="(objectClass=msDS-PasswordSettings)",
            base_dn=base,
            attributes=[
                "cn",
                "distinguishedName",
                "msDS-PasswordSettingsPrecedence",
                "msDS-MinimumPasswordLength",
                "msDS-MinimumPasswordAge",
                "msDS-MaximumPasswordAge",
                "msDS-PasswordHistoryLength",
                "msDS-LockoutThreshold",
                "msDS-LockoutDuration",
                "msDS-LockoutObservationWindow",
                "msDS-PasswordComplexityEnabled",
                "msDS-PSOAppliesTo",
            ],
            size_limit=limit,
        )
        return {"count": len(results), "policies": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_fsmo_roles() -> dict[str, Any]:
        """Report the current owner of each of the five FSMO roles."""
        roles: dict[str, Any] = {}
        for role, template in _FSMO_LOCATIONS.items():
            dn = template.format(base=settings.base_dn)
            try:
                obj = client.read_object(dn, attributes=["fSMORoleOwner"])
            except RuntimeError as exc:
                roles[role] = {"error": str(exc)}
                continue
            if obj is None:
                roles[role] = None
                continue
            roles[role] = {
                "container_dn": dn,
                "role_owner_dn": obj.get("attributes", {}).get("fSMORoleOwner"),
            }
        return {"base_dn": settings.base_dn, "roles": roles}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_trusts() -> dict[str, Any]:
        """List trust relationships defined for this domain (from CN=System)."""
        base = f"CN=System,{settings.base_dn}"
        results = client.search(
            search_filter="(objectClass=trustedDomain)",
            base_dn=base,
            attributes=TRUST_ATTRS,
        )
        for entry in results:
            attrs = entry.get("attributes", {})
            direction = attrs.get("trustDirection")
            ttype = attrs.get("trustType")
            if isinstance(direction, int):
                attrs["trustDirection_decoded"] = TRUST_DIRECTION.get(direction, str(direction))
            if isinstance(ttype, int):
                attrs["trustType_decoded"] = TRUST_TYPE.get(ttype, str(ttype))
        return {"count": len(results), "trusts": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_sites() -> dict[str, Any]:
        """List Active Directory sites, subnets, and site links."""
        # Sites live in the Configuration NC — we ask rootDSE for it via server_info.
        info = client.domain_info()
        config_nc = None
        for nc in info.get("naming_contexts", []) or []:
            if nc.startswith("CN=Configuration,"):
                config_nc = nc
                break
        if not config_nc:
            return {"error": "Could not locate Configuration naming context via rootDSE."}
        sites_dn = f"CN=Sites,{config_nc}"

        sites = client.search(
            search_filter="(objectClass=site)",
            base_dn=sites_dn,
            attributes=["cn", "distinguishedName", "description", "location"],
        )
        subnets = client.search(
            search_filter="(objectClass=subnet)",
            base_dn=f"CN=Subnets,{sites_dn}",
            attributes=["cn", "distinguishedName", "siteObject", "location"],
        )
        site_links = client.search(
            search_filter="(objectClass=siteLink)",
            base_dn=sites_dn,
            attributes=["cn", "distinguishedName", "siteList", "cost", "replInterval"],
        )
        return {
            "sites_container": sites_dn,
            "sites": sites,
            "subnets": subnets,
            "site_links": site_links,
        }
