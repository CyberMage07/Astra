"""Tests for Astra packer CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _packed_result() -> AnalysisResult:
    """Return a representative packed-file analysis result."""
    return AnalysisResult(
        analyzer="packer",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "is_likely_packed": True,
            "confidence": 95,
            "detected_packer": "UPX",
            "candidates": [
                {
                    "name": "UPX",
                    "confidence": 95,
                    "indicators": [
                        {
                            "indicator_type": "known-packer-section",
                            "description": "UPX section detected.",
                            "value": "UPX0",
                            "confidence": 90,
                            "severity": "high",
                            "location": "UPX0",
                        }
                    ],
                }
            ],
            "indicators": [
                {
                    "indicator_type": "known-packer-section",
                    "description": "UPX section detected.",
                    "value": "UPX0",
                    "confidence": 90,
                    "severity": "high",
                    "location": "UPX0",
                }
            ],
            "high_entropy_sections": 1,
            "executable_writable_sections": 1,
            "suspicious_section_names": 1,
            "import_count": 5,
            "overlay_size": 0,
        },
    )


def test_packer_command_displays_detection(tmp_path: Path) -> None:
    """The packer command should display detected packers and indicators."""
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.PackerAnalyzer.analyze",
        return_value=_packed_result(),
    ):
        result = runner.invoke(app, ["packer", str(sample)])

    assert result.exit_code == 0
    assert "Packer Detection" in result.stdout
    assert "UPX" in result.stdout
    assert "95%" in result.stdout
    assert "known-packer" in result.stdout
    assert "HIGH" in result.stdout


def test_packer_command_handles_clean_result(tmp_path: Path) -> None:
    """The packer command should report when no indicators are present."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    clean = AnalysisResult(
        analyzer="packer",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "is_likely_packed": False,
            "confidence": 0,
            "detected_packer": None,
            "candidates": [],
            "indicators": [],
            "high_entropy_sections": 0,
            "executable_writable_sections": 0,
            "suspicious_section_names": 0,
            "import_count": 100,
            "overlay_size": 0,
        },
    )

    with patch(
        "apps.cli.main.PackerAnalyzer.analyze",
        return_value=clean,
    ):
        result = runner.invoke(app, ["packer", str(sample)])

    assert result.exit_code == 0
    assert "No packing indicators detected" in result.stdout


def test_packer_command_handles_failure(tmp_path: Path) -> None:
    """The packer command should exit cleanly on analysis failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="packer",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.PackerAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["packer", str(sample)])

    assert result.exit_code == 1
    assert "Packer analysis failed" in result.stdout
