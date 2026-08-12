"""Tests for Astra delay/bound import CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_importdirectories_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display normalized import-directory data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="importdirectories",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "delay_import_directory_present": True,
            "bound_import_directory_present": True,
            "delay_library_count": 1,
            "delay_import_count": 1,
            "suspicious_delay_import_count": 1,
            "bound_library_count": 1,
            "malformed_bound_import_count": 0,
            "delay_libraries": [
                {
                    "library": "kernel32.dll",
                    "import_count": 1,
                    "suspicious_import_count": 1,
                    "imports": [
                        {
                            "library": "kernel32.dll",
                            "name": "CreateProcessW",
                            "ordinal": None,
                            "address": 0x140001000,
                            "imported_by_name": True,
                            "imported_by_ordinal": False,
                            "suspicious": True,
                        }
                    ],
                }
            ],
            "bound_imports": [
                {
                    "library": "kernel32.dll",
                    "timestamp": 123456,
                    "forwarder_count": 0,
                    "malformed": False,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ImportDirectoriesAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["importdirectories", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Delay/Bound Import Analysis" in cli_result.stdout
    assert "kernel32.dll" in cli_result.stdout
    assert "CreateProcessW" in cli_result.stdout


def test_importdirectories_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["importdirectories", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
