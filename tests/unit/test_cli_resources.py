"""Tests for Astra PE resource CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _resources_result() -> AnalysisResult:
    """Return a representative resource-analysis result."""
    return AnalysisResult(
        analyzer="resources",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "resource_count": 2,
            "resources": [
                {
                    "resource_type": "icon",
                    "type_name": "ICON",
                    "name": "1",
                    "language": "English",
                    "rva": 0x1000,
                    "offset": 0x400,
                    "size": 1024,
                    "entropy": 4.2,
                    "sha256": "a" * 64,
                    "is_executable": False,
                    "embedded_file_type": "png",
                    "is_high_entropy": False,
                },
                {
                    "resource_type": "manifest",
                    "type_name": "MANIFEST",
                    "name": "1",
                    "language": "English",
                    "rva": 0x2000,
                    "offset": 0x800,
                    "size": 512,
                    "entropy": 3.1,
                    "sha256": "b" * 64,
                    "is_executable": False,
                    "embedded_file_type": None,
                    "is_high_entropy": False,
                },
            ],
            "icon_count": 1,
            "manifest_count": 1,
            "version_count": 0,
            "rcdata_count": 0,
            "high_entropy_resources": 0,
            "embedded_executables": 0,
            "embedded_archives": 0,
            "embedded_documents": 0,
            "total_resource_bytes": 1536,
            "largest_resource_size": 1024,
        },
    )


def test_resources_command_displays_resources(
    tmp_path: Path,
) -> None:
    """The resources command should display normalized resources."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.ResourcesAnalyzer.analyze",
        return_value=_resources_result(),
    ):
        result = runner.invoke(
            app,
            ["resources", str(sample)],
        )

    assert result.exit_code == 0
    assert "PE Resource Analysis" in result.stdout
    assert "icon" in result.stdout
    assert "manifest" in result.stdout
    assert "English" in result.stdout
    assert "No suspicious PE resource indicators detected" in result.stdout


def test_resources_command_handles_failure(
    tmp_path: Path,
) -> None:
    """The resources command should exit cleanly on failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="resources",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.ResourcesAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(
            app,
            ["resources", str(sample)],
        )

    assert result.exit_code == 1
    assert "Resource analysis failed" in result.stdout


def test_resources_command_rejects_missing_file() -> None:
    """The resources command should handle missing files cleanly."""
    result = runner.invoke(
        app,
        ["resources", "/definitely/missing/sample.exe"],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
