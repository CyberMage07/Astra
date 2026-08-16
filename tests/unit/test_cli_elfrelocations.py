"""Tests for Astra ELF relocation CLI."""

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
    """Return one completed ELF relocation result."""
    return AnalysisResult(
        analyzer="elfrelocations",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=4,
        data={
            "relocation_sections_present": True,
            "relocation_section_count": 1,
            "relocation_count": 2,
            "rela_count": 2,
            "rel_count": 0,
            "symbol_relocation_count": 2,
            "imported_symbol_relocation_count": 2,
            "plt_relocation_count": 1,
            "got_relocation_count": 1,
            "malformed_relocation_count": 0,
            "relocation_types": [
                "R_X86_64_GLOB_DAT",
                "R_X86_64_JUMP_SLOT",
            ],
            "sections": [
                {
                    "name": ".rela.plt",
                    "section_type": "SHT_RELA",
                    "entry_count": 2,
                    "malformed_entry_count": 0,
                    "relocations": [],
                }
            ],
        },
    )


def test_elfrelocations_command_displays_result(
    tmp_path: Path,
) -> None:
    """CLI should display ELF relocation information."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "apps.cli.main.ELFRelocationsAnalyzer.analyze",
        return_value=_result(),
    ):
        result = runner.invoke(
            app,
            [
                "elfrelocations",
                str(sample),
            ],
        )

    assert result.exit_code == 0
    assert "ELF Relocation Analysis" in result.stdout
    assert "R_X86_64_GLOB_DAT" in result.stdout
    assert "R_X86_64_JUMP_SLOT" in result.stdout
    assert ".rela.plt" in result.stdout


def test_elfrelocations_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing samples should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfrelocations",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
