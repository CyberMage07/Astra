"""Central configuration for Astra."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AstraSettings(BaseSettings):
    """Validated Astra application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ASTRA_",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "testing", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    project_root: Path = Field(default_factory=lambda: Path.cwd())
    storage_root: Path = Path("storage")
    database_url: str = "sqlite:///database/astra.db"

    analysis_timeout: int = Field(default=60, ge=1, le=3600)
    max_sample_size_mb: int = Field(default=250, ge=1, le=4096)
    max_archive_depth: int = Field(default=5, ge=1, le=20)
    max_extracted_files: int = Field(default=2000, ge=1, le=100000)

    allow_network_access: bool = False
    enable_dynamic_analysis: bool = False

    @property
    def resolved_storage_root(self) -> Path:
        """Return the absolute storage directory."""
        if self.storage_root.is_absolute():
            return self.storage_root

        return self.project_root / self.storage_root

    def ensure_directories(self) -> None:
        """Create Astra runtime directories when missing."""
        directories = (
            self.resolved_storage_root,
            self.resolved_storage_root / "samples",
            self.resolved_storage_root / "quarantine",
            self.resolved_storage_root / "artifacts",
            self.resolved_storage_root / "reports",
            self.resolved_storage_root / "temp",
            self.project_root / "logs",
            self.project_root / "database",
        )

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> AstraSettings:
    """Return a cached settings instance."""
    settings = AstraSettings()
    settings.ensure_directories()
    return settings
