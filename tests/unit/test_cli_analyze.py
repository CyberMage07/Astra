"""Tests for Astra unified-analysis CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisReport,
    AnalysisResult,
    AnalysisStatus,
    AnalyzerExecution,
    FileHashes,
    FileTypeResult,
    Finding,
    Severity,
    ThreatAssessment,
    ThreatClassification,
)

runner = CliRunner()


def _report_with_findings(sample: Path) -> AnalysisReport:
    """Return a representative unified analysis report."""
    finding = Finding(
        title="Suspicious imported API: CreateRemoteThread",
        description="Creates a thread in another process.",
        category="process-injection",
        severity=Severity.HIGH,
        confidence=90,
        attack_techniques=("T1055",),
    )

    result = AnalysisResult(
        analyzer="imports",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        findings=(finding,),
    )

    return AnalysisReport(
        sample_path=sample,
        original_name=sample.name,
        size_bytes=2,
        hashes=FileHashes(
            md5="a" * 32,
            sha1="b" * 40,
            sha256="c" * 64,
            sha512="d" * 128,
        ),
        file_type=FileTypeResult(
            file_name=sample.name,
            extension=".exe",
            mime_type="application/vnd.microsoft.portable-executable",
            magic_description="PE32 executable",
            detected_family="pe",
            extension_matches=True,
            is_executable=True,
            confidence=100,
            source_path=sample,
        ),
        analyzer_results=(result,),
        analyzer_executions=(
            AnalyzerExecution(
                analyzer="imports",
                status="completed",
                duration_ms=5,
                finding_count=1,
                error_count=0,
            ),
        ),
        findings=(finding,),
        assessment=ThreatAssessment(
            score=78,
            classification=ThreatClassification.HIGH_RISK,
            confidence=92,
            reasons=("HIGH: Suspicious imported API: CreateRemoteThread",),
            attack_techniques=("T1055",),
        ),
        completed_analyzers=1,
        failed_analyzers=0,
        total_duration_ms=10,
    )


def test_analyze_command_displays_unified_report(
    tmp_path: Path,
) -> None:
    """The analyze command should display the unified report."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.AnalysisOrchestrator.analyze",
        return_value=_report_with_findings(sample),
    ):
        result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0
    assert "Astra Unified Analysis" in result.stdout
    assert "sample.exe" in result.stdout
    assert "Detected family" in result.stdout
    assert "Threat Assessment" in result.stdout
    assert "HIGH-RISK" in result.stdout
    assert "78 / 100" in result.stdout
    assert "92%" in result.stdout
    assert "Assessment Reasons" in result.stdout
    assert "Analyzer Execution" in result.stdout
    assert "Unified Findings" in result.stdout
    assert "process-injection" in result.stdout
    assert "CreateRemoteThread" in result.stdout
    assert "T1055" in result.stdout
    assert "HIGH" in result.stdout


def test_analyze_command_handles_no_findings(
    tmp_path: Path,
) -> None:
    """The analyze command should report when no indicators are found."""
    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"ok")

    report = AnalysisReport(
        sample_path=sample,
        original_name=sample.name,
        size_bytes=2,
        hashes=FileHashes(
            md5="a" * 32,
            sha1="b" * 40,
            sha256="c" * 64,
            sha512="d" * 128,
        ),
        file_type=FileTypeResult(
            file_name=sample.name,
            extension=".bin",
            mime_type="application/octet-stream",
            magic_description="data",
            detected_family="unknown",
            extension_matches=None,
            is_executable=False,
            confidence=25,
            source_path=sample,
        ),
        analyzer_results=(),
        analyzer_executions=(),
        findings=(),
        assessment=ThreatAssessment(
            score=0,
            classification=ThreatClassification.LIKELY_BENIGN,
            confidence=50,
            reasons=(),
            attack_techniques=(),
        ),
        completed_analyzers=0,
        failed_analyzers=0,
        total_duration_ms=1,
    )

    with patch(
        "apps.cli.main.AnalysisOrchestrator.analyze",
        return_value=report,
    ):
        result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0
    assert "Threat Assessment" in result.stdout
    assert "LIKELY-BENIGN" in result.stdout
    assert "0 / 100" in result.stdout
    assert "No suspicious indicators detected" in result.stdout


def test_analyze_command_rejects_missing_file() -> None:
    """A missing sample path should produce a non-zero exit."""
    result = runner.invoke(
        app,
        ["analyze", "/definitely/missing/sample.exe"],
    )

    assert result.exit_code != 0
