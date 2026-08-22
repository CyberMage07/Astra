"""Tests for Astra ELF packer CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elfpacker_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF packer analysis."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elfpacker",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "packed_score": 40,
            "packed_likelihood": "suspicious",
            "suspected_packer": "UPX",
            "known_packer_signature": True,
            "high_entropy_section_count": 1,
            "executable_high_entropy_count": 1,
            "rwx_section_count": 0,
            "suspicious_section_name_count": 1,
            "stripped": True,
            "symbol_table_present": False,
            "import_count": 4,
            "relocation_count": 20,
            "unusual_entry_point": False,
            "suspicious_dynamic_loading": False,
            "suspicious_layout": False,
            "evidence_count": 1,
            "indicators": [
                {
                    "name": "known-packer-signature",
                    "category": "packer-signature",
                    "description": "Known packer signature.",
                    "weight": 40,
                    "triggered": True,
                    "evidence": ["UPX"],
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFPackerAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elfpacker",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "ELF Packer & Obfuscation Analysis" in cli_result.stdout
    assert "40 / 100" in cli_result.stdout
    assert "UPX" in cli_result.stdout
    assert "known-packer-signature" in cli_result.stdout


def test_elfpacker_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfpacker",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
