"""CA configuration and role holder read-only queries over WinRM."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..winrm_source import ReadOnlyWinRMClient


_HEALTH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$svc = Get-Service certsvc
$out = [ordered]@{
  ServiceStatus = "$($svc.Status)"
  StartMode     = "$($svc.StartType)"
}
try {
  Import-Module PSPKI -ErrorAction Stop
  $ca = Get-CertificationAuthority | Select-Object -First 1
  $out.Name         = $ca.Name
  $out.ConfigString = $ca.ConfigString
  $out.Type         = "$($ca.Type)"
  $out.IsAccessible = $ca.IsAccessible
} catch {
  $out.PSPKIError = "$($_.Exception.Message)"
}
$out | ConvertTo-Json -Depth 4 -Compress
"""


def register(mcp: FastMCP, winrm: ReadOnlyWinRMClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def check_ca_hosts_health() -> dict[str, Any]:
        """Report certsvc status and reachability for every host in ADCS_CA_HOSTS.

        Fans out over all configured issuing CAs (e.g. CA-ISSUE01 and CA-ISSUE02)
        so you can see at a glance which CAs are online and responding to WinRM.
        """
        hosts = winrm.ca_hosts
        if not hosts:
            return {"checked": 0, "results": [], "note": "ADCS_CA_HOSTS is empty."}
        results: list[dict[str, Any]] = []
        for host in hosts:
            try:
                res = winrm.run_script(_HEALTH_SCRIPT, host=host)
                results.append({"host": host, "ok": True, "ca": res.get("result")})
            except Exception as exc:  # noqa: BLE001 — surface per-host failure
                results.append({"host": host, "ok": False, "error": str(exc)})
        online = sum(1 for r in results if r["ok"])
        return {"checked": len(results), "online": online, "results": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_ca_configuration(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return CA configuration: CRL settings, published URLs, allowed templates."""
        script = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = Get-CertificationAuthority | Select-Object -First 1
$out = [ordered]@{
  Name = $ca.Name
  ConfigString = $ca.ConfigString
  Type = "$($ca.Type)"
  IsAccessible = $ca.IsAccessible
  BaseCRLPublicationInterval = ($ca | Get-CACrlDistributionPoint | Select-Object URI, PublishToServer, PublishDeltaToServer, AddToCertificateCdp, AddToFreshestCrl, AddToCrlCdp, AddToCrlIdp)
  AIA = ($ca | Get-CAAuthorityInformationAccess | Select-Object URI, AddToCertificateAia, AddToCertificateOcsp)
  Templates = ($ca | Get-CATemplate | ForEach-Object { $_.Templates } | Select-Object Name, DisplayName, OID)
  CRLPeriod = ($ca | Get-CaCrlPublicationParameters)
}
$out | ConvertTo-Json -Depth 5 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_ca_role_holders(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return the identities in the CA's role assignments (Admins, Managers, etc.)."""
        script = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = Get-CertificationAuthority | Select-Object -First 1
$acl = $ca | Get-CertificationAuthorityAcl
$roles = $acl.Access | ForEach-Object {
  [pscustomobject]@{
    Identity = $_.IdentityReference.Value
    Rights   = "$($_.Rights)"
    Type     = "$($_.AccessControlType)"
  }
}
$roles | ConvertTo-Json -Depth 3 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_officer_rights(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return per-template Certificate Manager (officer) rights on the CA."""
        script = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = Get-CertificationAuthority | Select-Object -First 1
$rights = $ca | Get-CertificateManagerRights
$rights | Select-Object Identity, Rights, Templates | ConvertTo-Json -Depth 3 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_ca_certificate_chain(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return the CA's own certificate chain (issuer → root) as PEM."""
        script = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = Get-CertificationAuthority | Select-Object -First 1
$chain = $ca | Get-CertificationAuthorityCertificate
$chain | ForEach-Object {
  [pscustomobject]@{
    Subject = $_.Subject
    Issuer  = $_.Issuer
    Serial  = $_.SerialNumber
    NotBefore = $_.NotBefore
    NotAfter  = $_.NotAfter
    Pem = "-----BEGIN CERTIFICATE-----`n" + [System.Convert]::ToBase64String($_.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----"
  }
} | ConvertTo-Json -Depth 4 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_ca_backup_settings(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return CA registry-level settings (from HKLM\\...\\CertSvc\\Configuration)."""
        script = r"""
$ErrorActionPreference = 'Stop'
$svc = Get-Service certsvc
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caName = (Get-ChildItem $base | Select-Object -First 1).PSChildName
$key = Get-ItemProperty (Join-Path $base $caName)
$out = [ordered]@{
  CAName = $caName
  ServiceStatus = "$($svc.Status)"
  StartMode = "$($svc.StartType)"
  CACertPublicationURLs = $key.CACertPublicationURLs
  CRLPublicationURLs = $key.CRLPublicationURLs
  CRLPeriod = $key.CRLPeriod
  CRLPeriodUnits = $key.CRLPeriodUnits
  CRLDeltaPeriod = $key.CRLDeltaPeriod
  CRLDeltaPeriodUnits = $key.CRLDeltaPeriodUnits
  ValidityPeriod = $key.ValidityPeriod
  ValidityPeriodUnits = $key.ValidityPeriodUnits
  KRAFlags = $key.KRAFlags
  InterfaceFlags = $key.InterfaceFlags
  AuditFilter = $key.AuditFilter
}
$out | ConvertTo-Json -Depth 4 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)
