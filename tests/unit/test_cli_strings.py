"""Tests for Astra strings CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus, AnalyzerError

runner = CliRunner()


def _completed_result() -> AnalysisResult:
    """Return a representative strings-analysis result."""
    return AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=3,
        data={
            "strings": [
                {
                    "value": "AstraASCII",
                    "offset": 1,
                    "encoding": "ascii",
                    "length": 10,
                },
                {
                    "value": "PowerShellCommand",
                    "offset": 12,
                    "encoding": "utf-16-le",
                    "length": 17,
                },
            ],
            "total_count": 2,
            "truncated": False,
            "minimum_length": 4,
        },
    )


def test_strings_command_displays_results(tmp_path: Path) -> None:
    """The strings command should display normalized extracted strings."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    with patch(
        "apps.cli.main.StringsAnalyzer.analyze",
        return_value=_completed_result(),
    ):
        result = runner.invoke(app, ["strings", str(sample)])

    assert result.exit_code == 0
    assert "String Extraction Summary" in result.stdout
    assert "AstraASCII" in result.stdout
    assert "PowerShellCommand" in result.stdout
    assert "utf-16-le" in result.stdout


def test_strings_command_displays_truncation_notice(tmp_path: Path) -> None:
    """The strings command should report when results are truncated."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    truncated = _completed_result().model_copy(
        update={
            "data": {
                **_completed_result().data,
                "total_count": 10,
                "truncated": True,
            }
        }
    )

    with patch(
        "apps.cli.main.StringsAnalyzer.analyze",
        return_value=truncated,
    ):
        result = runner.invoke(app, ["strings", str(sample)])

    assert result.exit_code == 0
    assert "Showing the first 2 of 10 extracted strings" in result.stdout


def test_strings_command_handles_failed_analysis(tmp_path: Path) -> None:
    """The strings command should exit cleanly when extraction fails."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    failed = AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.PARTIAL,
        duration_ms=1,
        errors=(
            AnalyzerError(
                error_type="ReadError",
                message="Unable to read sample",
                recoverable=True,
            ),
        ),
    )

    with patch(
        "apps.cli.main.StringsAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["strings", str(sample)])

    assert result.exit_code == 1
    assert "String extraction failed" in result.stdout
    assert "Unable to read sample" in result.stdout
