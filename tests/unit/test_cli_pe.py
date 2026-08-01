"""Tests for Astra PE CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus, AnalyzerError

runner = CliRunner()


def _completed_result() -> AnalysisResult:
    """Return a representative successful PE analysis result."""
    return AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=15,
        data={
            "header": {
                "machine": "x86-64",
                "architecture_bits": 64,
                "subsystem": "Windows GUI",
                "image_base": 4194304,
                "entry_point": 4096,
                "compile_timestamp": 1700000000,
                "number_of_sections": 1,
                "characteristics": 34,
                "is_dll": False,
                "is_driver": False,
            },
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": 4096,
                    "virtual_size": 512,
                    "raw_size": 512,
                    "entropy": 6.25,
                    "characteristics": 1610612768,
                    "executable": True,
                    "writable": False,
                    "readable": True,
                }
            ],
            "imports": [
                {
                    "library": "KERNEL32.dll",
                    "function": "CreateFileW",
                    "address": 8192,
                    "ordinal": None,
                }
            ],
            "exports": [],
            "overlay_size": 128,
            "has_tls_callbacks": False,
            "has_debug_directory": False,
            "has_resources": True,
            "signed": True,
        },
    )


def test_pe_command_displays_analysis(tmp_path: Path) -> None:
    """The PE command should render normalized PE analysis data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch("apps.cli.main.PEAnalyzer.analyze", return_value=_completed_result()):
        result = runner.invoke(app, ["pe", str(sample)])

    assert result.exit_code == 0
    assert "PE Analysis Summary" in result.stdout
    assert "x86-64" in result.stdout
    assert "64-bit" in result.stdout
    assert ".text" in result.stdout
    assert "CreateFileW" in result.stdout


def test_pe_command_handles_failed_analysis(tmp_path: Path) -> None:
    """The PE command should exit cleanly when parsing fails."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed_result = AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
        errors=(
            AnalyzerError(
                error_type="PEFormatError",
                message="Invalid PE file",
                recoverable=False,
            ),
        ),
    )

    with patch("apps.cli.main.PEAnalyzer.analyze", return_value=failed_result):
        result = runner.invoke(app, ["pe", str(sample)])

    assert result.exit_code == 1
    assert "PE analysis failed" in result.stdout
    assert "Invalid PE file" in result.stdout
