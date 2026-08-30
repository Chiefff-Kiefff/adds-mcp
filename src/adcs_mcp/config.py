"""Configuration for the ADCS MCP server.

Reuses the AD DS LDAP configuration (ADDS_*) so the same service account
can read AD's PKI subtree (CN=Public Key Services,CN=Configuration,...).
Adds ADCS_* variables for WinRM access to online issuing CAs.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from adds_mcp.config import Settings as ADDSSettings


class ADCSSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ADCS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Online issuing CA hosts reachable via WinRM.
    ca_hosts: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # WinRM credentials. Prefer Kerberos with a keytab in production.
    winrm_user: str = ""
    winrm_password: str = ""
    winrm_auth: Literal["negotiate", "kerberos", "ntlm", "basic", "credssp"] = "negotiate"
    winrm_port: int = 5986
    winrm_use_https: bool = True
    winrm_cert_validation: bool = True
    winrm_read_timeout: int = 60
    winrm_operation_timeout: int = 45

    # CRL/AIA web server leg. Optional list of HTTP(S) CDP/AIA URLs to
    # health-check (the http:// distribution points baked into issued certs).
    crl_aia_urls: Annotated[list[str], NoDecode] = Field(default_factory=list)
    web_timeout: int = 20
    web_tls_validate: bool = True
    web_ca_cert_file: str = ""
    # Max revoked entries to sample when summarising a fetched CRL.
    web_max_crl_sample: int = 25

    # HTTP transport.
    http_host: str = "0.0.0.0"
    http_port: int = 8081

    # Safety caps for CA database queries.
    max_certs_per_query: int = 500

    @field_validator("ca_hosts", "crl_aia_urls", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    def require_winrm_ready(self) -> None:
        required = {
            "ADCS_CA_HOSTS": self.ca_hosts,
            "ADCS_WINRM_USER": self.winrm_user,
        }
        # A Kerberos keytab (or an ambient ticket cache) means no password is
        # stored here; every other auth mode needs one.
        if self.winrm_auth != "kerberos":
            required["ADCS_WINRM_PASSWORD"] = self.winrm_password
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(
                "ADCS WinRM configuration missing: "
                + ", ".join(missing)
                + ". Populate them in the environment or .env file."
            )


adds_settings = ADDSSettings()
adcs_settings = ADCSSettings()
