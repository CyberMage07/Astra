"""Tests for Astra ELF symbol CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def _result() -> AnalysisResult:
    """Return a completed ELF symbol result."""
    return AnalysisResult(
        analyzer="elfsymbols",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "symbol_tables_present": True,
            "symbol_count": 2,
            "dynamic_symbol_count": 2,
            "static_symbol_count": 0,
            "import_count": 2,
            "export_count": 0,
            "weak_symbol_count": 0,
            "suspicious_symbol_count": 1,
            "duplicate_symbol_count": 0,
            "malformed_symbol_count": 0,
            "stripped": True,
            "symbols": [
                {
                    "name": "printf",
                    "value": 0,
                    "size": 0,
                    "binding": "STB_GLOBAL",
                    "symbol_type": "STT_FUNC",
                    "visibility": "STV_DEFAULT",
                    "section_index": "SHN_UNDEF",
                    "imported": True,
                    "exported": False,
                    "weak": False,
                    "suspicious": False,
                    "suspicious_category": None,
                },
                {
                    "name": "execve",
                    "value": 0,
                    "size": 0,
                    "binding": "STB_GLOBAL",
                    "symbol_type": "STT_FUNC",
                    "visibility": "STV_DEFAULT",
                    "section_index": "SHN_UNDEF",
                    "imported": True,
                    "exported": False,
                    "weak": False,
                    "suspicious": True,
                    "suspicious_category": ("process-execution"),
                },
            ],
        },
    )


def test_elfsymbols_command_displays_result(
    tmp_path: Path,
) -> None:
    """CLI should display normalized ELF symbol data."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "apps.cli.main.ELFSymbolsAnalyzer.analyze",
        return_value=_result(),
    ):
        result = runner.invoke(
            app,
            [
                "elfsymbols",
                str(sample),
            ],
        )

    assert result.exit_code == 0
    assert "ELF Symbol Analysis" in result.stdout
    assert "execve" in result.stdout
    assert "process-execution" in result.stdout


def test_elfsymbols_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfsymbols",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
