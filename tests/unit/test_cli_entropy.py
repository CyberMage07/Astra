"""Tests for Astra entropy CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    Evidence,
    Finding,
    Severity,
)

runner = CliRunner()


def _completed_result_with_findings() -> AnalysisResult:
    """Return a representative entropy result with findings."""
    return AnalysisResult(
        analyzer="entropy",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=3,
        findings=(
            Finding(
                title="High overall file entropy",
                description="The file has high entropy.",
                category="entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="overall-entropy",
                        value="8.00",
                        location="entire file",
                    ),
                ),
            ),
        ),
        data={
            "overall_entropy": 8.0,
            "file_size": 8192,
            "block_size": 4096,
            "regions": [
                {
                    "offset": 0,
                    "size": 4096,
                    "entropy": 8.0,
                },
                {
                    "offset": 4096,
                    "size": 4096,
                    "entropy": 8.0,
                },
            ],
            "high_entropy_regions": 2,
            "maximum_region_entropy": 8.0,
        },
    )


def test_entropy_command_displays_findings(tmp_path: Path) -> None:
    """The entropy command should display analysis and findings."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    with patch(
        "apps.cli.main.EntropyAnalyzer.analyze",
        return_value=_completed_result_with_findings(),
    ):
        result = runner.invoke(app, ["entropy", str(sample)])

    assert result.exit_code == 0
    assert "Entropy Analysis" in result.stdout
    assert "8.0000" in result.stdout
    assert "HIGH" in result.stdout
    assert "High overall file entropy" in result.stdout


def test_entropy_command_handles_no_findings(tmp_path: Path) -> None:
    """The entropy command should report when no indicators are detected."""
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"clean")

    completed = AnalysisResult(
        analyzer="entropy",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "overall_entropy": 0.0,
            "file_size": 5,
            "block_size": 4096,
            "regions": [
                {
                    "offset": 0,
                    "size": 5,
                    "entropy": 0.0,
                }
            ],
            "high_entropy_regions": 0,
            "maximum_region_entropy": 0.0,
        },
    )

    with patch(
        "apps.cli.main.EntropyAnalyzer.analyze",
        return_value=completed,
    ):
        result = runner.invoke(app, ["entropy", str(sample)])

    assert result.exit_code == 0
    assert "No high-entropy indicators detected" in result.stdout


def test_entropy_command_rejects_invalid_block_size(tmp_path: Path) -> None:
    """The entropy command should fail for an invalid block size."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    result = runner.invoke(
        app,
        ["entropy", str(sample), "--block-size", "0"],
    )

    assert result.exit_code != 0
