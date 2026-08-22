"""Tests for Astra ELF versioning CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elfversioning_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF symbol-versioning analysis."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elfversioning",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=4,
        data={
            "versioning_present": True,
            "versym_present": True,
            "verneed_present": True,
            "verdef_present": False,
            "required_library_count": 1,
            "required_version_count": 2,
            "defined_version_count": 0,
            "versioned_symbol_count": 2,
            "imported_versioned_symbol_count": 2,
            "exported_versioned_symbol_count": 0,
            "glibc_version_count": 2,
            "glibcxx_version_count": 0,
            "cxxabi_version_count": 0,
            "highest_glibc_version": "GLIBC_2.38",
            "highest_glibcxx_version": None,
            "highest_cxxabi_version": None,
            "malformed_entry_count": 0,
            "requirements": [
                {
                    "library": "libc.so.6",
                    "version": "GLIBC_2.34",
                    "version_index": 2,
                    "hidden": False,
                },
                {
                    "library": "libc.so.6",
                    "version": "GLIBC_2.38",
                    "version_index": 3,
                    "hidden": False,
                },
            ],
            "definitions": [],
            "bindings": [
                {
                    "symbol": "memcpy",
                    "version": "GLIBC_2.14",
                    "version_index": 4,
                    "imported": True,
                    "exported": False,
                    "hidden": False,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFVersioningAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elfversioning",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "GNU Symbol Versioning" in cli_result.stdout
    assert "GLIBC_2.38" in cli_result.stdout
    assert "libc.so.6" in cli_result.stdout


def test_elfversioning_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfversioning",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
