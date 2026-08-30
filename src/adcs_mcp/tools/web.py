"""CRL / AIA web server tools (the HTTPS leg of the PKI).

These fetch CRLs and CA certificates from the HTTP(S) distribution points that
issued certificates point at, decode them, and report whether the served CRL is
still current. This is the client's-eye view of revocation and chain building,
complementing the LDAP view (what AD publishes) and the WinRM view (what the CA
holds).
"""

from __future__ import annotations

import base64
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..cert_utils import parse_certificate, parse_crl
from ..config import adcs_settings
from ..http_source import PkiWebClient

_READONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _looks_like_crl(content_type: str | None, url: str) -> bool:
    ct = (content_type or "").lower()
    if "crl" in ct:
        return True
    if "x509-ca-cert" in ct or "pkix-cert" in ct or "x-x509" in ct:
        return False
    return url.lower().endswith(".crl")


def register(mcp: FastMCP, web: PkiWebClient) -> None:
    @mcp.tool(annotations=_READONLY)
    def fetch_crl(
        url: Annotated[
            str,
            Field(description="HTTP(S) URL of a CRL (e.g. an http:// CDP endpoint)."),
        ],
    ) -> dict[str, Any]:
        """Download a CRL over HTTP(S) and summarise its freshness and revocations.

        Reports reachability plus ``this_update`` / ``next_update`` / ``is_expired``
        so you can confirm the published CRL is current, not stale.
        """
        fetched = web.get(url)
        crl = parse_crl(fetched.pop("content"), sample_limit=adcs_settings.web_max_crl_sample)
        return {"fetch": fetched, "crl": crl}

    @mcp.tool(annotations=_READONLY)
    def fetch_ca_certificate(
        url: Annotated[
            str,
            Field(description="HTTP(S) URL of a CA certificate (an AIA endpoint, .crt/.cer)."),
        ],
    ) -> dict[str, Any]:
        """Download a CA certificate from an AIA endpoint over HTTP(S) and decode it."""
        fetched = web.get(url)
        cert = parse_certificate(fetched.pop("content"))
        return {"fetch": fetched, "certificate": cert}

    @mcp.tool(annotations=_READONLY)
    def check_crl_aia_endpoints(
        urls: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    "CDP/AIA URLs to probe. Defaults to ADCS_CRL_AIA_URLS when omitted."
                ),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Probe each CRL/AIA web endpoint for reachability and (for CRLs) freshness.

        Returns one result per URL: ``ok`` on success with freshness/expiry for
        CRLs, or ``error`` with the failure reason. Use this for an at-a-glance
        health check of the PKI web server leg.
        """
        targets = urls or adcs_settings.crl_aia_urls
        if not targets:
            return {
                "checked": 0,
                "results": [],
                "note": (
                    "No URLs supplied and ADCS_CRL_AIA_URLS is empty. Pass 'urls' or "
                    "populate ADCS_CRL_AIA_URLS with your CDP/AIA HTTP endpoints."
                ),
            }
        results: list[dict[str, Any]] = []
        for target in targets:
            entry: dict[str, Any] = {"url": target}
            try:
                fetched = web.get(target)
            except Exception as exc:  # noqa: BLE001 — surface any failure per-URL
                results.append({**entry, "ok": False, "error": str(exc)})
                continue
            content = fetched.pop("content")
            entry.update(
                {
                    "ok": True,
                    "status_code": fetched["status_code"],
                    "content_type": fetched["content_type"],
                    "content_length": fetched["content_length"],
                    "elapsed_ms": fetched["elapsed_ms"],
                }
            )
            try:
                if _looks_like_crl(fetched["content_type"], fetched["final_url"]):
                    crl = parse_crl(content, sample_limit=0)
                    entry.update(
                        {
                            "kind": "crl",
                            "issuer_cn": crl["issuer_cn"],
                            "this_update": crl["this_update"],
                            "next_update": crl["next_update"],
                            "is_expired": crl["is_expired"],
                            "seconds_until_next_update": crl["seconds_until_next_update"],
                            "revoked_count": crl["revoked_count"],
                        }
                    )
                else:
                    cert = parse_certificate(content)
                    entry.update(
                        {
                            "kind": "certificate",
                            "subject_cn": cert["subject_cn"],
                            "not_valid_after": cert["not_valid_after"],
                        }
                    )
            except Exception as exc:  # noqa: BLE001 — reachable but unparseable
                entry["parse_error"] = str(exc)
            results.append(entry)
        return {"checked": len(results), "results": results}

    @mcp.tool(
        annotations={**_READONLY, "openWorldHint": False},
    )
    def parse_crl_pem(
        pem: Annotated[
            str,
            Field(
                description=(
                    "PEM-encoded CRL ('-----BEGIN X509 CRL-----' block) or a base64 "
                    "DER blob. Use for CRLs exported from an offline Root/Policy CA."
                )
            ),
        ],
    ) -> dict[str, Any]:
        """Decode a CRL (issuer, this/next update, revoked entries) without fetching it."""
        data = pem.encode()
        if b"-----BEGIN" not in data:
            try:
                data = base64.b64decode("".join(pem.split()))
            except Exception:  # noqa: BLE001
                pass
        return parse_crl(data, sample_limit=adcs_settings.web_max_crl_sample)
