"""Tests for Astra PE relocation CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_relocations_command_displays_result(
    tmp_path: Path,
) -> None:
    """The relocations command should display normalized data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="relocations",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "relocation_directory_present": True,
            "block_count": 1,
            "relocation_count": 1,
            "mapped_relocation_count": 1,
            "executable_relocation_count": 1,
            "writable_relocation_count": 0,
            "malformed_relocation_count": 0,
            "unknown_type_count": 0,
            "relocation_types": ["DIR64"],
            "unusually_large_relocation_table": False,
            "blocks": [
                {
                    "index": 0,
                    "page_rva": 0x1000,
                    "block_size": 12,
                    "entry_count": 1,
                    "malformed_entry_count": 0,
                    "entries": [],
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.RelocationsAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["relocations", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Relocation Analysis" in cli_result.stdout
    assert "DIR64" in cli_result.stdout
    assert "0x1000" in cli_result.stdout


def test_relocations_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["relocations", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
