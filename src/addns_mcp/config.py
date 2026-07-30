"""Configuration for addns-mcp. Reuses ADDS_* for the LDAPS bind."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict

from adds_mcp.config import Settings as ADDSSettings


class ADDNSSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ADDNS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    http_host: str = "0.0.0.0"
    http_port: int = 8082

    max_records_per_query: int = 500


adds_settings = ADDSSettings()
addns_settings = ADDNSSettings()
