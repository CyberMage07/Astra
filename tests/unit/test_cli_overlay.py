"""Tests for Astra overlay CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_overlay_command_displays_result(
    tmp_path: Path,
) -> None:
    """The overlay command should display normalized results."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="overlay",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "overlay_present": True,
            "offset": 4096,
            "size": 1024,
            "percentage_of_file": 20.0,
            "entropy": 7.5,
            "sha256": "a" * 64,
            "embedded_file_type": "zip",
            "is_executable": False,
            "is_archive": True,
            "is_high_entropy": True,
            "is_large": False,
            "is_certificate_table": False,
            "is_installer_payload": False,
            "installer_type": None,
        },
    )

    with patch(
        "apps.cli.main.OverlayAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["overlay", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Overlay Analysis" in cli_result.stdout
    assert "Overlay present" in cli_result.stdout
    assert "Yes" in cli_result.stdout
    assert "zip" in cli_result.stdout


def test_overlay_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The overlay command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["overlay", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
