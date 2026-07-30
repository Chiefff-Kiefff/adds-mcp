"""Standalone X.509 parsing tools (no directory or WinRM access needed)."""

from __future__ import annotations

import base64
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..cert_utils import parse_certificate


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    def parse_certificate_pem(
        pem: Annotated[
            str,
            Field(
                description=(
                    "PEM-encoded certificate ('-----BEGIN CERTIFICATE-----' block). "
                    "Or a base64 blob (DER). Newlines are optional for base64 input."
                )
            ),
        ],
    ) -> dict[str, Any]:
        """Decode a certificate into subject/issuer/EKU/SAN/validity/fingerprints."""
        data = pem.encode()
        if b"-----BEGIN CERTIFICATE-----" not in data:
            # Try base64-decoded DER.
            try:
                data = base64.b64decode("".join(pem.split()))
            except Exception:  # noqa: BLE001
                pass
        return parse_certificate(data)
