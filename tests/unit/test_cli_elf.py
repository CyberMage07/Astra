"""Tests for Astra ELF CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def _elf_result() -> AnalysisResult:
    """Return one completed ELF result."""
    return AnalysisResult(
        analyzer="elf",
        analyzer_version="0.1.0",
        status=(AnalysisStatus.COMPLETED),
        duration_ms=3,
        data={
            "elf_present": True,
            "header": {
                "architecture_bits": 64,
                "endianness": "little",
                "elf_type": "ET_DYN",
                "machine": "x86-64",
                "os_abi": "System V",
                "abi_version": 0,
                "elf_version": 1,
                "entry_point": 0x5540,
                "program_header_offset": 64,
                "section_header_offset": 1000,
                "program_header_count": 15,
                "section_header_count": 29,
                "flags": 0,
            },
            "sections": [],
            "segments": [],
            "section_count": 29,
            "segment_count": 15,
            "dynamic": {
                "dynamically_linked": True,
                "interpreter": ("/lib64/ld-linux-x86-64.so.2"),
                "needed_libraries": ["libc.so.6"],
                "soname": None,
                "rpath": None,
                "runpath": None,
                "bind_now": True,
                "dynamic_entry_count": 20,
            },
            "security": {
                "pie": True,
                "nx_enabled": True,
                "executable_stack": False,
                "relro": True,
                "full_relro": True,
                "bind_now": True,
                "stripped": True,
                "has_stack_canary": True,
                "has_rpath": False,
                "has_runpath": False,
            },
            "malformed": False,
            "malformed_section_count": 0,
            "malformed_segment_count": 0,
        },
    )


def test_elf_command_displays_result(
    tmp_path: Path,
) -> None:
    """The ELF command should display normalized data."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "apps.cli.main.ELFAnalyzer.analyze",
        return_value=_elf_result(),
    ):
        result = runner.invoke(
            app,
            [
                "elf",
                str(sample),
            ],
        )

    assert result.exit_code == 0
    assert "ELF Static Analysis" in result.stdout
    assert "x86-64" in result.stdout
    assert "libc.so.6" in result.stdout
    assert "Full" in result.stdout


def test_elf_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elf",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
