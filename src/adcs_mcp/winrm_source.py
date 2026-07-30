"""WinRM/PowerShell source for querying online issuing CAs.

Uses pypsrp for PowerShell remoting. All scripts are read-only and use
Out-Json (or ConvertTo-Json) so the results parse cleanly on this side.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from .config import ADCSSettings

log = logging.getLogger(__name__)


class WinRMUnavailable(RuntimeError):
    """Raised when pypsrp is not installed but a WinRM tool is invoked."""


try:  # optional dependency — only required if you use WinRM-backed tools
    from pypsrp.client import Client as _PypsrpClient  # type: ignore
    from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore
    from pypsrp.wsman import WSMan  # type: ignore

    _PYPSRP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PypsrpClient = None  # type: ignore
    PowerShell = RunspacePool = WSMan = None  # type: ignore
    _PYPSRP_AVAILABLE = False


class ReadOnlyWinRMClient:
    """Lazily-connected WinRM PowerShell runner, one runspace per CA host."""

    def __init__(self, settings: ADCSSettings) -> None:
        self._settings = settings
        self._lock = threading.Lock()

    def _require_pypsrp(self) -> None:
        if not _PYPSRP_AVAILABLE:
            raise WinRMUnavailable(
                "pypsrp is not installed. Install with 'pip install .[adcs]' "
                "or add pypsrp to your environment to enable WinRM-backed tools."
            )

    @contextmanager
    def _runspace(self, host: str) -> Iterator[Any]:
        self._require_pypsrp()
        self._settings.require_winrm_ready()
        wsman = WSMan(
            host,
            username=self._settings.winrm_user,
            password=self._settings.winrm_password,
            auth=self._settings.winrm_auth,
            port=self._settings.winrm_port,
            ssl=self._settings.winrm_use_https,
            cert_validation=self._settings.winrm_cert_validation,
            read_timeout=self._settings.winrm_read_timeout,
            operation_timeout=self._settings.winrm_operation_timeout,
        )
        with wsman, RunspacePool(wsman) as pool:
            yield pool

    def resolve_host(self, host: str | None) -> str:
        """Pick a CA host if the caller didn't specify one."""
        if host:
            if host not in self._settings.ca_hosts and self._settings.ca_hosts:
                log.warning(
                    "Requested CA host %s is not in ADCS_CA_HOSTS %s; running anyway.",
                    host,
                    self._settings.ca_hosts,
                )
            return host
        if not self._settings.ca_hosts:
            self._settings.require_winrm_ready()
        return self._settings.ca_hosts[0]

    def run_script(
        self,
        script: str,
        host: str | None = None,
        parse_json: bool = True,
    ) -> Any:
        """Run a PowerShell script on the given CA host and return the parsed result.

        The script must emit valid JSON on stdout (typically via ``ConvertTo-Json -Depth N``).
        Stderr is preserved and raised if the script fails.
        """
        target = self.resolve_host(host)
        with self._lock, self._runspace(target) as pool:
            ps = PowerShell(pool)
            ps.add_script(script)
            output = ps.invoke()
            if ps.had_errors:
                errors = "\n".join(str(e) for e in ps.streams.error)
                raise RuntimeError(f"PowerShell on {target} failed: {errors}")
            text_parts = [str(item) for item in output if item is not None]
            text = "\n".join(text_parts).strip()
            if not parse_json:
                return {"host": target, "stdout": text}
            if not text:
                return {"host": target, "result": None}
            try:
                return {"host": target, "result": json.loads(text)}
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"PowerShell on {target} did not return valid JSON: {exc}. "
                    f"First 500 chars: {text[:500]!r}"
                ) from exc


PYPSRP_AVAILABLE = _PYPSRP_AVAILABLE
