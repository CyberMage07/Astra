"""Tests for Astra PE section CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _sections_result() -> AnalysisResult:
    """Return a representative section-analysis result."""
    return AnalysisResult(
        analyzer="sections",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "section_count": 2,
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": 0x1000,
                    "virtual_size": 4096,
                    "raw_offset": 1024,
                    "raw_size": 4096,
                    "entropy": 6.2,
                    "characteristics": 0x60000000,
                    "readable": True,
                    "writable": False,
                    "executable": True,
                    "is_rwx": False,
                    "is_wx": False,
                    "is_empty": False,
                    "has_virtual_raw_anomaly": False,
                    "is_suspicious_name": False,
                    "is_executable_resource": False,
                },
                {
                    "name": ".data",
                    "virtual_address": 0x2000,
                    "virtual_size": 8192,
                    "raw_offset": 5120,
                    "raw_size": 512,
                    "entropy": 4.1,
                    "characteristics": 0xC0000000,
                    "readable": True,
                    "writable": True,
                    "executable": False,
                    "is_rwx": False,
                    "is_wx": False,
                    "is_empty": False,
                    "has_virtual_raw_anomaly": True,
                    "is_suspicious_name": False,
                    "is_executable_resource": False,
                },
            ],
            "high_entropy_sections": 0,
            "executable_sections": 1,
            "writable_sections": 1,
            "rwx_sections": 0,
            "wx_sections": 0,
            "suspicious_name_sections": 0,
            "empty_executable_sections": 0,
            "virtual_raw_anomalies": 1,
            "executable_resource_sections": 0,
        },
    )


def test_sections_command_displays_sections(
    tmp_path: Path,
) -> None:
    """The sections command should display normalized PE sections."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.SectionsAnalyzer.analyze",
        return_value=_sections_result(),
    ):
        result = runner.invoke(
            app,
            ["sections", str(sample)],
        )

    assert result.exit_code == 0
    assert "PE Section Analysis" in result.stdout
    assert ".text" in result.stdout
    assert ".data" in result.stdout
    assert "Layout anomaly" in result.stdout
    assert "No suspicious PE section indicators detected" in result.stdout


def test_sections_command_handles_failure(
    tmp_path: Path,
) -> None:
    """The sections command should exit cleanly on analyzer failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="sections",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.SectionsAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(
            app,
            ["sections", str(sample)],
        )

    assert result.exit_code == 1
    assert "Section analysis failed" in result.stdout


def test_sections_command_rejects_missing_file() -> None:
    """The sections command should handle missing files cleanly."""
    result = runner.invoke(
        app,
        ["sections", "/definitely/missing/sample.exe"],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
