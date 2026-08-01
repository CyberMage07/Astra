"""Tests for Astra configuration."""

from pathlib import Path

from packages.config import AstraSettings


def test_default_settings(tmp_path: Path) -> None:
    """Default settings should resolve paths beneath the project root."""
    settings = AstraSettings(project_root=tmp_path)

    assert settings.env == "development"
    assert settings.analysis_timeout == 60
    assert settings.resolved_storage_root == tmp_path / "storage"
    assert settings.allow_network_access is False
    assert settings.enable_dynamic_analysis is False


def test_runtime_directories_are_created(tmp_path: Path) -> None:
    """Astra should create all required runtime directories."""
    settings = AstraSettings(project_root=tmp_path)
    settings.ensure_directories()

    expected_directories = (
        tmp_path / "storage",
        tmp_path / "storage" / "samples",
        tmp_path / "storage" / "quarantine",
        tmp_path / "storage" / "artifacts",
        tmp_path / "storage" / "reports",
        tmp_path / "storage" / "temp",
        tmp_path / "logs",
        tmp_path / "database",
    )

    assert all(directory.is_dir() for directory in expected_directories)
