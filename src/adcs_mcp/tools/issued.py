"""CA database (issued / pending / revoked / failed) via WinRM."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..winrm_source import ReadOnlyWinRMClient

# Common ADCS Disposition values.
# 8  = Failed, 9  = Denied, 12 = Issued (pending revocation),
# 15 = Revoked, 16 = Certificate issued, 20 = Certificate issued (Issued state),
# 21 = CA certificate. 9 = Pending. See MS-WCCE / ICertRequest::GetRequestId.
_DISPOSITIONS = {
    "issued": 20,
    "pending": 9,
    "denied": 30,
    "failed": 31,
    "revoked": 21,
}

_PS_LIST_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = if ($Env:CA_CONFIG) {{ $Env:CA_CONFIG }} else {{ (Get-CertificationAuthority | Select-Object -First 1).ConfigString }}
$filter = @()
{disposition_filter}
{extra_filters}
$props = @(
  'RequestID','Request.RequesterName','CommonName','SerialNumber',
  'NotBefore','NotAfter','CertificateTemplate','CertificateTemplateOid',
  'Request.SubmittedWhen','Request.ResolvedWhen','Request.Disposition',
  'Request.DispositionMessage','Request.RevokedWhen','Request.RevokedReason'
)
$rows = Get-CertificationAuthority -ConfigString $ca |
  Get-IssuedRequest -Property $props @(if ($filter.Count) {{ '-Filter'; $filter }})
$rows | Select-Object -First {limit} $props | ConvertTo-Json -Depth 4 -Compress
"""


def _build_list_script(disposition: str | None, limit: int, extra_filters: list[str]) -> str:
    disp_snippet = ""
    if disposition:
        disp_snippet = (
            f"$filter += 'Request.Disposition -eq {_DISPOSITIONS[disposition]}'"
        )
    extra_snippet = "\n".join(f"$filter += '{f}'" for f in extra_filters)
    return _PS_LIST_TEMPLATE.format(
        disposition_filter=disp_snippet,
        extra_filters=extra_snippet,
        limit=limit,
    )


def register(mcp: FastMCP, winrm: ReadOnlyWinRMClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_issued_certificates(
        ca_host: Annotated[str, Field(default="")] = "",
        requester: Annotated[
            str,
            Field(
                default="",
                description="Optional requester filter, e.g. 'CORP\\\\jsmith'.",
            ),
        ] = "",
        template: Annotated[
            str,
            Field(default="", description="Optional certificate template name filter."),
        ] = "",
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List issued certificates from a CA's database (dispositions=Issued)."""
        extras: list[str] = []
        if requester:
            extras.append(f"Request.RequesterName -eq {requester}")
        if template:
            extras.append(f"CertificateTemplate -eq {template}")
        script = _build_list_script("issued", limit, extras)
        return winrm.run_script(script, host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_pending_requests(
        ca_host: Annotated[str, Field(default="")] = "",
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List pending certificate requests on the CA."""
        return winrm.run_script(_build_list_script("pending", limit, []), host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_failed_requests(
        ca_host: Annotated[str, Field(default="")] = "",
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List failed / denied certificate requests on the CA."""
        return winrm.run_script(_build_list_script("failed", limit, []), host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_revoked_certificates(
        ca_host: Annotated[str, Field(default="")] = "",
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List revoked certificates from the CA database."""
        return winrm.run_script(_build_list_script("revoked", limit, []), host=ca_host or None)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_certificate_by_serial(
        serial_hex: Annotated[str, Field(description="Certificate serial number (hex).")],
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Fetch a single issued certificate by serial number, including its PEM."""
        script = f"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = if ($Env:CA_CONFIG) {{ $Env:CA_CONFIG }} else {{ (Get-CertificationAuthority | Select-Object -First 1).ConfigString }}
$row = Get-CertificationAuthority -ConfigString $ca |
  Get-IssuedRequest -Filter "SerialNumber -eq {serial_hex}" -Property RequestID,SerialNumber,CommonName,NotBefore,NotAfter,CertificateTemplate,RawCertificate |
  Select-Object -First 1
$row | ConvertTo-Json -Depth 4 -Compress
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
    def count_certificates_by_disposition(
        ca_host: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return counts of certificates on the CA grouped by disposition."""
        script = r"""
$ErrorActionPreference = 'Stop'
Import-Module PSPKI -ErrorAction Stop
$ca = if ($Env:CA_CONFIG) { $Env:CA_CONFIG } else { (Get-CertificationAuthority | Select-Object -First 1).ConfigString }
$labels = @{ 8='Failed';9='Pending';12='Issued(RevokedPending)';15='Revoked';20='Issued';21='CACert';30='Denied';31='Failed' }
$rows = Get-CertificationAuthority -ConfigString $ca |
  Get-IssuedRequest -Property 'Request.Disposition' -Filter 'RequestID -gt 0'
$grouped = $rows | Group-Object -Property {$labels[[int]$_.'Request.Disposition']} |
  Select-Object Name, Count
$grouped | ConvertTo-Json -Depth 3 -Compress
"""
        return winrm.run_script(script, host=ca_host or None)
