"""Tests for Astra PE fingerprint CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_fingerprints_command_displays_result(
    tmp_path: Path,
) -> None:
    """The fingerprints command should display fingerprint data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="fingerprints",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "fingerprint_available": True,
            "imphash": "a" * 32,
            "import_library_count": 1,
            "import_count": 1,
            "named_import_count": 1,
            "ordinal_import_count": 0,
            "malformed_import_count": 0,
            "fingerprint_source": "kernel32.createfilew",
            "libraries": [
                {
                    "name": "kernel32.dll",
                    "import_count": 1,
                    "named_import_count": 1,
                    "ordinal_import_count": 0,
                    "imports": [],
                }
            ],
            "rich_header_hash": None,
            "section_hash": None,
            "authentihash": None,
            "tlsh": None,
            "ssdeep": None,
        },
    )

    with patch(
        "apps.cli.main.FingerprintsAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["fingerprints", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Fingerprint Analysis" in cli_result.stdout
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in cli_result.stdout
    assert "kernel32.dll" in cli_result.stdout
    assert "kernel32.createfilew" in cli_result.stdout


def test_fingerprints_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The fingerprints command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["fingerprints", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
