"""Tests for Astra YARA CLI analysis."""

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


def _completed_result() -> AnalysisResult:
    """Return a representative successful YARA analysis result."""
    return AnalysisResult(
        analyzer="yara",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=2,
        findings=(
            Finding(
                title="YARA rule matched: Astra_Test_String",
                description="Harmless test rule.",
                category="testing",
                severity=Severity.INFO,
                confidence=90,
                evidence=(
                    Evidence(
                        kind="yara-string",
                        value="ASTRA_YARA_TEST_MARKER",
                        location="offset 0x0",
                        metadata={"identifier": "$marker"},
                    ),
                ),
            ),
        ),
        data={
            "rules_root": "/tmp/rules/yara",
            "match_count": 1,
            "matches": [],
        },
    )


def test_yara_command_displays_match(tmp_path: Path) -> None:
    """The YARA command should display findings and evidence."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    with patch(
        "apps.cli.main.YaraAnalyzer.analyze",
        return_value=_completed_result(),
    ):
        result = runner.invoke(app, ["yara", str(sample)])

    assert result.exit_code == 0
    assert "YARA Analysis" in result.stdout
    assert "Astra_Test_String" in result.stdout
    assert "testing" in result.stdout
    assert "ASTRA_YARA_TEST_MARKER" in result.stdout
    assert "$marker" in result.stdout


def test_yara_command_handles_no_matches(tmp_path: Path) -> None:
    """The YARA command should report a clean no-match result."""
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"clean")

    completed = AnalysisResult(
        analyzer="yara",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "rules_root": "/tmp/rules/yara",
            "match_count": 0,
            "matches": [],
        },
    )

    with patch(
        "apps.cli.main.YaraAnalyzer.analyze",
        return_value=completed,
    ):
        result = runner.invoke(app, ["yara", str(sample)])

    assert result.exit_code == 0
    assert "No YARA matches found" in result.stdout


def test_yara_command_handles_failure(tmp_path: Path) -> None:
    """The YARA command should exit cleanly on analyzer failure."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")

    failed = AnalysisResult(
        analyzer="yara",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
        errors=(),
    )

    with patch(
        "apps.cli.main.YaraAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["yara", str(sample)])

    assert result.exit_code == 1
    assert "YARA scan failed" in result.stdout
