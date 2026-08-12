"""Tests for Astra version-information CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_versioninfo_command_displays_result(
    tmp_path: Path,
) -> None:
    """The versioninfo command should display normalized metadata."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="versioninfo",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "version_info_present": True,
            "company_name": "Astra Security",
            "file_description": "Example application",
            "file_version": "1.0.0",
            "original_filename": "sample.exe",
            "product_name": "Astra",
            "product_version": "1.0",
            "original_filename_matches": True,
            "suspicious_company_name": False,
            "suspicious_product_name": False,
            "missing_identity_fields": False,
            "string_count": 6,
        },
    )

    with patch(
        "apps.cli.main.VersionInfoAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["versioninfo", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Version Information Analysis" in cli_result.stdout
    assert "Astra Security" in cli_result.stdout
    assert "sample.exe" in cli_result.stdout


def test_versioninfo_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The versioninfo command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["versioninfo", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
