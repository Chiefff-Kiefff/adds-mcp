"""Thin, read-only wrapper around ldap3 for Active Directory queries."""

from __future__ import annotations

import logging
import ssl
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from ldap3 import (
    ALL,
    ALL_ATTRIBUTES,
    BASE,
    Connection,
    LEVEL,
    SAFE_SYNC,
    SUBTREE,
    Server,
    ServerPool,
    Tls,
)
from ldap3.core.exceptions import LDAPException

from .config import Settings
from .formatting import format_entry

log = logging.getLogger(__name__)

# 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
_FILETIME_EPOCH_DELTA = 116444736000000000

SCOPE_MAP = {"base": BASE, "one": LEVEL, "level": LEVEL, "sub": SUBTREE, "subtree": SUBTREE}


class ReadOnlyADClient:
    """Manages a single, lazily-created ldap3 connection for read-only queries."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._connection: Connection | None = None

    # ------------------------------------------------------------------ setup
    def _build_tls(self) -> Tls:
        validate = ssl.CERT_REQUIRED if self._settings.tls_validate else ssl.CERT_NONE
        kwargs: dict[str, Any] = {"validate": validate, "version": ssl.PROTOCOL_TLS_CLIENT}
        if self._settings.ca_cert_file:
            kwargs["ca_certs_file"] = self._settings.ca_cert_file
        return Tls(**kwargs)

    def _build_pool(self) -> ServerPool:
        tls = self._build_tls()
        servers = [
            Server(
                host,
                port=self._settings.port,
                use_ssl=True,
                tls=tls,
                get_info=ALL,
                connect_timeout=self._settings.query_timeout_seconds,
            )
            for host in self._settings.servers
        ]
        return ServerPool(servers, pool_strategy="FIRST", active=True, exhaust=True)

    def _connect(self) -> Connection:
        self._settings.require_ready()
        pool = self._build_pool()
        conn = Connection(
            pool,
            user=self._settings.bind_dn,
            password=self._settings.bind_password,
            auto_bind=True,
            client_strategy=SAFE_SYNC,
            read_only=True,
            receive_timeout=self._settings.query_timeout_seconds,
            raise_exceptions=True,
        )
        log.info("Bound to AD as %s via %s", self._settings.bind_dn, self._settings.servers)
        return conn

    def _get_connection(self) -> Connection:
        with self._lock:
            if self._connection is None or not self._connection.bound:
                self._connection = self._connect()
            return self._connection

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.unbind()
                except LDAPException:
                    pass
                self._connection = None

    # ---------------------------------------------------------------- queries
    def search(
        self,
        *,
        search_filter: str,
        base_dn: str | None = None,
        scope: str = "subtree",
        attributes: Iterable[str] | str | None = ALL_ATTRIBUTES,
        page_size: int | None = None,
        size_limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Perform a paged LDAP search and return decoded entries."""
        conn = self._get_connection()
        scope_val = SCOPE_MAP.get(scope.lower(), SUBTREE)
        base = base_dn or self._settings.base_dn
        page = page_size or self._settings.default_page_size
        cap = min(
            size_limit if size_limit else self._settings.max_page_size,
            self._settings.max_page_size,
        )

        if isinstance(attributes, str):
            attrs: Any = attributes
        elif attributes is None:
            attrs = ALL_ATTRIBUTES
        else:
            attrs = list(attributes)

        try:
            results: list[dict[str, Any]] = []
            for entry in conn.extend.standard.paged_search(
                search_base=base,
                search_filter=search_filter,
                search_scope=scope_val,
                attributes=attrs,
                paged_size=min(page, cap),
                generator=True,
                get_operational_attributes=True,
            ):
                if entry.get("type") != "searchResEntry":
                    continue
                results.append(format_entry(entry))
                if len(results) >= cap:
                    break
            return results
        except LDAPException as exc:
            raise RuntimeError(f"LDAP search failed: {exc}") from exc

    def read_object(
        self,
        dn: str,
        attributes: Iterable[str] | str | None = ALL_ATTRIBUTES,
    ) -> dict[str, Any] | None:
        """Read a single object by DN. Returns None if not found."""
        results = self.search(
            search_filter="(objectClass=*)",
            base_dn=dn,
            scope="base",
            attributes=attributes,
            page_size=1,
            size_limit=1,
        )
        return results[0] if results else None

    def domain_info(self) -> dict[str, Any]:
        """Return rootDSE + domain naming context info."""
        conn = self._get_connection()
        info = conn.server.info
        schema = {}
        if info is not None:
            schema = {
                "vendor_name": getattr(info, "vendor_name", None),
                "vendor_version": getattr(info, "vendor_version", None),
                "naming_contexts": list(getattr(info, "naming_contexts", []) or []),
                "supported_ldap_versions": list(
                    getattr(info, "supported_ldap_versions", []) or []
                ),
                "supported_sasl_mechanisms": list(
                    getattr(info, "supported_sasl_mechanisms", []) or []
                ),
                "alt_servers": list(getattr(info, "alt_servers", []) or []),
            }
        return schema


# ---------------------------------------------------------------------- filters


def escape_filter(value: str) -> str:
    """RFC 4515 escape a value for use inside an LDAP filter."""
    if value is None:
        return ""
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\5c")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def escape_dn(value: str) -> str:
    """Escape a DN component for embedding into a search base."""
    if value is None:
        return ""
    # DNs need different escaping than filters; only the most dangerous characters.
    return value.replace("\\", "\\\\").replace(",", "\\,")


def to_filetime(dt: datetime) -> int:
    """Convert a UTC datetime into a Windows FILETIME integer."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    epoch_seconds = (dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
    return int(epoch_seconds * 10_000_000) + _FILETIME_EPOCH_DELTA


def filetime_days_ago(days: int) -> int:
    """FILETIME representing now minus ``days`` days."""
    return to_filetime(datetime.now(timezone.utc) - timedelta(days=days))
