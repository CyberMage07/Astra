"""Tests for Astra PE export CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_exports_command_displays_result(
    tmp_path: Path,
) -> None:
    """The exports command should display normalized export data."""
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="exports",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "export_directory_present": True,
            "module_name": "sample.dll",
            "export_count": 1,
            "named_export_count": 1,
            "ordinal_only_count": 0,
            "forwarded_export_count": 0,
            "executable_export_count": 1,
            "unmapped_export_count": 0,
            "suspicious_name_count": 0,
            "malformed_export_count": 0,
            "duplicate_name_count": 0,
            "duplicate_ordinal_count": 0,
            "unusually_large_export_table": False,
            "exports": [
                {
                    "ordinal": 1,
                    "name": "Initialize",
                    "address": 0x140001000,
                    "rva": 0x1000,
                    "forwarder": None,
                    "is_forwarded": False,
                    "section_name": ".text",
                    "is_mapped": True,
                    "is_executable": True,
                    "suspicious_name": False,
                    "malformed": False,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ExportsAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["exports", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Export Analysis" in cli_result.stdout
    assert "sample.dll" in cli_result.stdout
    assert "Initialize" in cli_result.stdout
    assert ".text" in cli_result.stdout


def test_exports_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The exports command should reject missing samples."""
    sample = tmp_path / "missing.dll"

    cli_result = runner.invoke(
        app,
        ["exports", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
