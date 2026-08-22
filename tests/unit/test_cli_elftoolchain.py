"""Tests for Astra ELF toolchain CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_elftoolchain_command_displays_result(
    tmp_path: Path,
) -> None:
    """The command should display ELF toolchain analysis."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    result = AnalysisResult(
        analyzer="elftoolchain",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=4,
        data={
            "toolchain_detected": True,
            "primary_compiler": "GCC",
            "compiler_version": "16.1.1",
            "linker": None,
            "linker_version": None,
            "language": None,
            "runtime": None,
            "gcc_detected": True,
            "clang_detected": False,
            "rust_detected": False,
            "go_detected": False,
            "lto_detected": False,
            "comment_section_present": True,
            "comment_entry_count": 1,
            "build_id": "0123456789abcdef",
            "compiler_marker_count": 1,
            "linker_marker_count": 0,
            "runtime_marker_count": 0,
            "language_marker_count": 0,
            "malformed_entry_count": 0,
            "markers": [
                {
                    "category": "compiler",
                    "value": "GCC: (GNU) 16.1.1",
                    "source": ".comment",
                    "confidence": 95,
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.ELFToolchainAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "elftoolchain",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "Build Provenance" in cli_result.stdout
    assert "GCC" in cli_result.stdout
    assert "16.1.1" in cli_result.stdout
    assert ".comment" in cli_result.stdout


def test_elftoolchain_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing ELF files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elftoolchain",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
