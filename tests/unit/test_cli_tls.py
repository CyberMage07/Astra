"""Tests for Astra TLS CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_tls_command_displays_result(
    tmp_path: Path,
) -> None:
    """The TLS command should display normalized callback data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="tls",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "tls_present": True,
            "callback_count": 1,
            "callbacks": [
                {
                    "index": 0,
                    "virtual_address": 0x140001000,
                    "relative_virtual_address": 0x1000,
                    "file_offset": 0x400,
                    "section_name": ".text",
                    "is_mapped": True,
                    "is_executable": True,
                    "is_writable": False,
                    "is_outside_image": False,
                }
            ],
            "address_of_callbacks": 0x140002000,
            "mapped_callbacks": 1,
            "executable_callbacks": 1,
            "writable_callbacks": 0,
            "outside_image_callbacks": 0,
            "suspicious_callbacks": 0,
        },
    )

    with patch(
        "apps.cli.main.TLSAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["tls", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE TLS Callback Analysis" in cli_result.stdout
    assert "TLS present" in cli_result.stdout
    assert ".text" in cli_result.stdout


def test_tls_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The TLS command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["tls", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
