"""Tests for Astra PE manifest CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_manifest_command_displays_result(
    tmp_path: Path,
) -> None:
    """The manifest command should display normalized data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="manifest",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "manifest_present": True,
            "manifest_count": 1,
            "requested_execution_level": "requireAdministrator",
            "ui_access": False,
            "requires_administrator": True,
            "highest_available": False,
            "as_invoker": False,
            "auto_elevate": False,
            "dpi_aware": True,
            "long_path_aware": None,
            "supported_os_count": 1,
            "supported_os_ids": ["{11111111-1111-1111-1111-111111111111}"],
            "dependency_count": 1,
            "dependencies": [
                {
                    "name": "Microsoft.Windows.Common-Controls",
                    "version": "6.0.0.0",
                    "processor_architecture": "*",
                    "public_key_token": "6595b64144ccf1df",
                    "language": None,
                    "dependency_type": "win32",
                }
            ],
            "requested_privileges_present": True,
            "malformed": False,
            "raw_manifest_count": 1,
        },
    )

    with patch(
        "apps.cli.main.ManifestAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["manifest", str(sample)],
        )

    assert cli_result.exit_code == 0

    output = cli_result.stdout

    assert "PE Application Manifest Analysis" in output
    assert "Manifest present" in output
    assert "requireAdministrator" in output
    assert "Requires administrator" in output
    assert "Supported OS entries" in output
    assert "Manifest Dependencies (1)" in output
    assert "Microsoft.Windows" in output
    assert "6.0.0.0" in output
    assert "6595b64144ccf1df" in output
    assert "No suspicious PE manifest indicators detected." in output


def test_manifest_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["manifest", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
