"""Tests for Astra IOC CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _ioc_result() -> AnalysisResult:
    """Return a representative IOC analysis result."""
    return AnalysisResult(
        analyzer="ioc",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "total_indicators": 3,
            "unique_indicators": 3,
            "summaries": [
                {
                    "indicator_type": "url",
                    "count": 1,
                    "indicators": [],
                },
                {
                    "indicator_type": "domain",
                    "count": 1,
                    "indicators": [],
                },
                {
                    "indicator_type": "ipv4",
                    "count": 1,
                    "indicators": [],
                },
            ],
            "indicators": [
                {
                    "indicator_type": "url",
                    "value": "https://evil.example/payload",
                    "source_string": "https://evil.example/payload",
                    "offset": 100,
                    "confidence": 90,
                    "tags": ["ioc", "url"],
                },
                {
                    "indicator_type": "domain",
                    "value": "evil.example",
                    "source_string": "evil.example",
                    "offset": 200,
                    "confidence": 75,
                    "tags": ["ioc", "domain"],
                },
                {
                    "indicator_type": "ipv4",
                    "value": "203.0.113.25",
                    "source_string": "connect 203.0.113.25",
                    "offset": 300,
                    "confidence": 85,
                    "tags": ["ioc", "ipv4"],
                },
            ],
        },
    )


def test_ioc_command_displays_indicators(tmp_path: Path) -> None:
    """The IOC command should display extracted indicators."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.IOCAnalyzer.analyze",
        return_value=_ioc_result(),
    ):
        result = runner.invoke(app, ["ioc", str(sample)])

    assert result.exit_code == 0
    assert "IOC Extraction" in result.stdout
    assert "https://evil.example/payload" in result.stdout
    assert "evil.example" in result.stdout
    assert "203.0.113.25" in result.stdout
    assert "90%" in result.stdout


def test_ioc_command_handles_no_indicators(tmp_path: Path) -> None:
    """The IOC command should report when no indicators are found."""
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"clean")

    completed = AnalysisResult(
        analyzer="ioc",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "total_indicators": 0,
            "unique_indicators": 0,
            "summaries": [],
            "indicators": [],
        },
    )

    with patch(
        "apps.cli.main.IOCAnalyzer.analyze",
        return_value=completed,
    ):
        result = runner.invoke(app, ["ioc", str(sample)])

    assert result.exit_code == 0
    assert "No indicators of compromise detected" in result.stdout


def test_ioc_command_handles_failure(tmp_path: Path) -> None:
    """The IOC command should exit cleanly on analyzer failure."""
    sample = tmp_path / "invalid.bin"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="ioc",
        analyzer_version="0.1.0",
        status=AnalysisStatus.PARTIAL,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.IOCAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["ioc", str(sample)])

    assert result.exit_code == 1
    assert "IOC analysis failed" in result.stdout
