"""Tests for Astra suspicious import CLI analysis."""

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
    """Return a representative import-analysis result."""
    return AnalysisResult(
        analyzer="imports",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=4,
        findings=(
            Finding(
                title="Suspicious imported API: CreateRemoteThread",
                description="Creates a thread in another process.",
                category="process-injection",
                severity=Severity.HIGH,
                confidence=90,
                evidence=(
                    Evidence(
                        kind="pe-import",
                        value="CreateRemoteThread",
                        location="KERNEL32.dll",
                    ),
                ),
                attack_techniques=("T1055",),
            ),
        ),
        data={
            "total_imports": 25,
            "suspicious_imports": 1,
            "behaviors": [
                {
                    "category": "process-injection",
                    "count": 1,
                    "maximum_severity": "high",
                    "indicators": [],
                }
            ],
            "indicators": [],
        },
    )


def test_imports_command_displays_findings(tmp_path: Path) -> None:
    """The imports command should display suspicious APIs and behaviors."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.ImportAnalyzer.analyze",
        return_value=_completed_result(),
    ):
        result = runner.invoke(app, ["imports", str(sample)])

    assert result.exit_code == 0
    assert "Import Behavior Analysis" in result.stdout
    assert "CreateRemote" in result.stdout
    assert "process-injection" in result.stdout
    assert "T1055" in result.stdout
    assert "HIGH" in result.stdout


def test_imports_command_handles_no_findings(tmp_path: Path) -> None:
    """The imports command should report when no suspicious APIs are found."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    completed = AnalysisResult(
        analyzer="imports",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "total_imports": 10,
            "suspicious_imports": 0,
            "behaviors": [],
            "indicators": [],
        },
    )

    with patch(
        "apps.cli.main.ImportAnalyzer.analyze",
        return_value=completed,
    ):
        result = runner.invoke(app, ["imports", str(sample)])

    assert result.exit_code == 0
    assert "No suspicious imported APIs detected" in result.stdout


def test_imports_command_handles_failure(tmp_path: Path) -> None:
    """The imports command should exit cleanly on analyzer failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="imports",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.ImportAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(app, ["imports", str(sample)])

    assert result.exit_code == 1
    assert "Import analysis failed" in result.stdout
