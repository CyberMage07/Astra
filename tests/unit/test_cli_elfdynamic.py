"""Tests for Astra ELF dynamic-linking CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elfdynamic_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF dynamic-linking analysis."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elfdynamic",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=2,
        data={
            "dynamic_linking_present": True,
            "plt_present": True,
            "plt_got_present": False,
            "plt_sec_present": False,
            "got_present": True,
            "got_plt_present": True,
            "plt_section_count": 1,
            "got_section_count": 2,
            "plt_entry_count": 16,
            "got_entry_estimate": 20,
            "plt_relocation_count": 15,
            "plt_got_address": 0x404000,
            "jmprel_address": 0x400600,
            "plt_relocation_size": 360,
            "plt_relocation_type": "DT_RELA",
            "bind_now": True,
            "lazy_binding": False,
            "relro": True,
            "full_relro": True,
            "writable_got": True,
            "malformed_entry_count": 0,
            "suspicious_dynamic_linking": False,
            "sections": [
                {
                    "name": ".plt",
                    "section_type": "SHT_PROGBITS",
                    "address": 0x401020,
                    "offset": 0x1020,
                    "size": 256,
                    "entry_size": 16,
                    "flags": 0x6,
                    "writable": False,
                    "executable": True,
                    "allocatable": True,
                    "entry_count": 16,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFDynamicLinkingAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elfdynamic",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "ELF Dynamic Linking" in cli_result.stdout
    assert "DT_RELA" in cli_result.stdout
    assert "Full RELRO" in cli_result.stdout
    assert ".plt" in cli_result.stdout


def test_elfdynamic_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfdynamic",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
