"""Configuration management for bbot scanner."""

from __future__ import annotations

import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class BbotScannerConfig(BaseSettings):
    """Configuration for bbot scanner agent."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    backend_url: str = "http://backend:8000"
    api_key: str = ""
    poll_interval: int = 60  # seconds
    log_level: str = "INFO"


def load_config() -> BbotScannerConfig:
    """Load configuration from environment variables."""
    return BbotScannerConfig()
