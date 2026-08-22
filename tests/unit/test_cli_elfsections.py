"""Tests for Astra ELF section CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elfsections_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF section analysis."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elfsections",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=4,
        data={
            "section_count": 1,
            "executable_section_count": 1,
            "writable_section_count": 0,
            "rwx_section_count": 0,
            "high_entropy_section_count": 0,
            "suspicious_name_count": 0,
            "zero_sized_mapped_count": 0,
            "overlapping_section_count": 0,
            "out_of_bounds_section_count": 0,
            "malformed_section_count": 0,
            "unusually_large_section_table": False,
            "average_entropy": 6.2,
            "maximum_entropy": 6.2,
            "sections": [
                {
                    "index": 1,
                    "name": ".text",
                    "section_type": "SHT_PROGBITS",
                    "address": 0x401000,
                    "offset": 0x1000,
                    "size": 4096,
                    "flags": 0x6,
                    "alignment": 16,
                    "entropy": 6.2,
                    "allocatable": True,
                    "executable": True,
                    "writable": False,
                    "rwx": False,
                    "high_entropy": False,
                    "suspicious_name": False,
                    "zero_sized_mapped": False,
                    "overlapping": False,
                    "out_of_bounds": False,
                    "malformed": False,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFSectionsAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elfsections",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "ELF Section Entropy" in cli_result.stdout
    assert ".text" in cli_result.stdout
    assert "6.200" in cli_result.stdout


def test_elfsections_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfsections",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
