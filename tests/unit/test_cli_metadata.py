"""Tests for Astra metadata CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _metadata_result() -> AnalysisResult:
    """Return a representative metadata result."""
    return AnalysisResult(
        analyzer="metadata",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "entries": [],
            "entry_count": 5,
            "company_name": "Astra Labs",
            "product_name": "Astra Sample",
            "file_description": "Representative executable",
            "original_filename": "sample.exe",
            "internal_name": None,
            "product_version": "1.0",
            "file_version": "1.0.0.0",
            "legal_copyright": None,
            "language": "language=0x0409, codepage=1200",
            "compile_timestamp": 1704067200,
            "compile_datetime": "2024-01-01T00:00:00Z",
            "has_version_info": True,
            "suspicious_timestamp": False,
            "future_timestamp": False,
        },
    )


def test_metadata_command_displays_fields(tmp_path: Path) -> None:
    """The metadata command should display normalized fields."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.MetadataAnalyzer.analyze",
        return_value=_metadata_result(),
    ):
        result = runner.invoke(app, ["metadata", str(sample)])

    assert result.exit_code == 0
    assert "Metadata Analysis" in result.stdout
    assert "Astra Labs" in result.stdout
    assert "Astra Sample" in result.stdout
    assert "Representative executable" in result.stdout
    assert "1.0.0.0" in result.stdout


def test_metadata_command_handles_missing_version_info(
    tmp_path: Path,
) -> None:
    """The metadata command should handle absent normalized metadata."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result_data = _metadata_result().model_copy(
        update={
            "data": {
                **_metadata_result().data,
                "entries": [],
                "entry_count": 1,
                "company_name": None,
                "product_name": None,
                "file_description": None,
                "original_filename": None,
                "product_version": None,
                "file_version": None,
                "language": None,
                "has_version_info": False,
            }
        }
    )

    with patch(
        "apps.cli.main.MetadataAnalyzer.analyze",
        return_value=result_data,
    ):
        result = runner.invoke(app, ["metadata", str(sample)])

    assert result.exit_code == 0
    assert "No normalized version metadata found" in result.stdout


def test_metadata_command_handles_failure(tmp_path: Path) -> None:
    """The metadata command should exit cleanly on failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="metadata",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.MetadataAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["metadata", str(sample)])

    assert result.exit_code == 1
    assert "Metadata analysis failed" in result.stdout
