"""Tests for Astra ELF fingerprint CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elffingerprints_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF fingerprints."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elffingerprints",
        analyzer_version="0.1.0",
        status=(AnalysisStatus.COMPLETED),
        duration_ms=3,
        data={
            "fingerprint_available": True,
            "import_fingerprint": "a" * 64,
            "library_fingerprint": "b" * 64,
            "section_fingerprint": "c" * 64,
            "combined_fingerprint": "d" * 64,
            "build_id": "0123456789abcdef",
            "imported_symbol_count": 10,
            "needed_library_count": 2,
            "section_count": 20,
            "source_count": 3,
            "sources": [
                {
                    "name": "imports",
                    "item_count": 10,
                    "normalized_source": "connect,execve",
                    "sha256": "a" * 64,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFFingerprintsAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elffingerprints",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "ELF Fingerprint Analysis" in cli_result.stdout
    assert "Combined fingerprint" in cli_result.stdout
    assert "0123456789abcdef" in cli_result.stdout


def test_elffingerprints_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elffingerprints",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
