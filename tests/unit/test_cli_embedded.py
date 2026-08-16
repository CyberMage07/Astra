"""Tests for Astra embedded-payload CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_embedded_command_displays_result(
    tmp_path: Path,
) -> None:
    """The embedded command should display recursive payload data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="embedded",
        analyzer_version="0.2.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=10,
        data={
            "embedded_payloads_present": True,
            "payload_count": 1,
            "analyzed_payload_count": 1,
            "executable_payload_count": 1,
            "archive_payload_count": 0,
            "document_payload_count": 0,
            "script_payload_count": 0,
            "duplicate_payload_count": 0,
            "skipped_payload_count": 0,
            "maximum_depth_reached": 1,
            "total_extracted_bytes": 128,
            "recursion_limit_reached": False,
            "payload_limit_reached": False,
            "byte_limit_reached": False,
            "limits": {
                "maximum_depth": 3,
                "maximum_payloads": 64,
                "maximum_payload_size": 67108864,
                "maximum_total_extracted_bytes": 268435456,
            },
            "payloads": [
                {
                    "index": 0,
                    "parent_index": None,
                    "depth": 1,
                    "location": {
                        "source": "resource",
                        "offset": 256,
                        "size": 128,
                        "resource_type": "10",
                        "resource_name": "1",
                        "parent_section": None,
                    },
                    "identity": {
                        "sha256": "a" * 64,
                        "detected_family": "pe",
                        "mime_type": ("application/vnd.microsoft.portable-executable"),
                        "magic_description": ("PE32 executable"),
                        "extension": None,
                        "is_executable": True,
                    },
                    "entropy": 6.5,
                    "extraction_method": "pe-resource",
                    "duplicate": False,
                    "truncated": False,
                    "analysis": {
                        "analyzed": True,
                        "analyzer_count": 23,
                        "completed_analyzers": 23,
                        "failed_analyzers": 0,
                        "finding_count": 2,
                        "classification": "suspicious",
                        "risk_score": 55,
                        "confidence": 80,
                    },
                }
            ],
        },
    )

    with patch(
        "apps.cli.main.EmbeddedAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "embedded",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "Recursive Embedded Payload Analysis" in cli_result.stdout
    assert "Payloads" in cli_result.stdout
    assert "pe" in cli_result.stdout
    assert "suspicious" in cli_result.stdout


def test_embedded_command_displays_empty_result(
    tmp_path: Path,
) -> None:
    """The embedded command should handle samples without children."""
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="embedded",
        analyzer_version="0.2.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "embedded_payloads_present": False,
            "payload_count": 0,
            "analyzed_payload_count": 0,
            "executable_payload_count": 0,
            "archive_payload_count": 0,
            "document_payload_count": 0,
            "script_payload_count": 0,
            "duplicate_payload_count": 0,
            "skipped_payload_count": 0,
            "maximum_depth_reached": 0,
            "total_extracted_bytes": 0,
            "recursion_limit_reached": False,
            "payload_limit_reached": False,
            "byte_limit_reached": False,
            "limits": {
                "maximum_depth": 3,
                "maximum_payloads": 64,
                "maximum_payload_size": 67108864,
                "maximum_total_extracted_bytes": 268435456,
            },
            "payloads": [],
        },
    )

    with patch(
        "apps.cli.main.EmbeddedAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            [
                "embedded",
                str(sample),
            ],
        )

    assert cli_result.exit_code == 0
    assert "No suspicious embedded payload" in cli_result.stdout


def test_embedded_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        [
            "embedded",
            str(sample),
        ],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
