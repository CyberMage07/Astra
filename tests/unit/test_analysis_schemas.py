"""Tests for Astra common analysis schemas."""

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    Severity,
)


def test_completed_analysis_result() -> None:
    """A completed analyzer result should preserve findings and evidence."""
    evidence = Evidence(
        kind="import",
        value="CreateRemoteThread",
        location="import table",
    )

    finding = Finding(
        title="Process injection API detected",
        description="The sample imports an API commonly associated with process injection.",
        category="process-injection",
        severity=Severity.HIGH,
        confidence=85,
        evidence=(evidence,),
        tags=("windows", "injection"),
        attack_techniques=("T1055",),
    )

    result = AnalysisResult(
        analyzer="test-analyzer",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=42,
        findings=(finding,),
        data={"family": "pe"},
    )

    assert result.status is AnalysisStatus.COMPLETED
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].evidence[0].value == "CreateRemoteThread"
    assert result.data["family"] == "pe"


def test_failed_analysis_result() -> None:
    """A failed analysis should carry a structured error."""
    error = AnalyzerError(
        error_type="ParseError",
        message="Unable to parse malformed sample.",
        recoverable=False,
    )

    result = AnalysisResult(
        analyzer="test-analyzer",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=5,
        errors=(error,),
    )

    assert result.status is AnalysisStatus.FAILED
    assert result.errors[0].recoverable is False
