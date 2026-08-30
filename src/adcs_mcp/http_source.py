"""HTTP(S) source for the CRL/AIA web server leg of the PKI.

Enterprise CAs publish their CRLs and CA certificates to HTTP distribution
points (the ``http://pki.corp.example.com/...`` URLs baked into every issued
certificate's CDP and AIA extensions). Clients fetch them over HTTP/HTTPS to
build chains and check revocation, so being able to reach those endpoints the
same way — and confirm the CRL they serve is current — is a core piece of
"insight into CS" that the LDAP (what AD publishes) and WinRM (what the CA
holds) halves do not cover.

All requests are plain GETs; nothing here mutates state.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .config import ADCSSettings

log = logging.getLogger(__name__)

# CA certs and CRLs are small; refuse to buffer anything unreasonable so a
# misdirected URL (an HTML error page, a huge file) can't exhaust memory.
_MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024


class PkiWebClient:
    """Fetches CRLs and CA certificates from HTTP(S) distribution points."""

    def __init__(self, settings: ADCSSettings) -> None:
        self._settings = settings

    def _verify(self) -> bool | str:
        if not self._settings.web_tls_validate:
            return False
        return self._settings.web_ca_cert_file or True

    def get(self, url: str) -> dict[str, Any]:
        """GET a URL and return the raw body plus fetch metadata.

        Raises ``ValueError`` for a non-HTTP scheme and ``RuntimeError`` for a
        transport failure, an error status, or an over-large body.
        """
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(
                f"Only http(s) URLs are supported for PKI web fetches; got {url!r}."
            )
        started = time.monotonic()
        try:
            resp = requests.get(
                url,
                timeout=self._settings.web_timeout,
                verify=self._verify(),
                stream=True,
                headers={"User-Agent": "adcs-mcp/pki-web-check"},
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(f"TLS verification failed for {url}: {exc}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach {url}: {exc}") from exc

        with resp:
            content = b""
            for chunk in resp.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > _MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        f"Response from {url} exceeded {_MAX_DOWNLOAD_BYTES} bytes; "
                        "refusing to buffer. Is the URL pointing at the right file?"
                    )
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"{url} returned HTTP {resp.status_code} {resp.reason} "
                    f"after {elapsed_ms} ms."
                )
            return {
                "url": url,
                "final_url": resp.url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("Content-Type"),
                "content_length": len(content),
                "elapsed_ms": elapsed_ms,
                "content": content,
            }
