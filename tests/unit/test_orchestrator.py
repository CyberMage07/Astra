"""Tests for Astra unified analysis orchestration."""

from pathlib import Path
from unittest.mock import patch

import pytest

from packages.core import AnalysisOrchestrator
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    FileHashes,
    FileTypeResult,
    Finding,
    Severity,
)


def _completed_result(
    analyzer: str,
    *,
    findings: tuple[Finding, ...] = (),
) -> AnalysisResult:
    """Return a representative completed analyzer result."""
    return AnalysisResult(
        analyzer=analyzer,
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        findings=findings,
    )


def test_orchestrator_runs_pe_pipeline(tmp_path: Path) -> None:
    """PE samples should trigger all relevant analyzers."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    file_type = FileTypeResult(
        file_name="sample.exe",
        extension=".exe",
        mime_type="application/vnd.microsoft.portable-executable",
        magic_description="PE32 executable",
        detected_family="pe",
        extension_matches=True,
        is_executable=True,
        confidence=100,
        source_path=sample,
    )

    hashes = FileHashes(
        md5="a" * 32,
        sha1="b" * 40,
        sha256="c" * 64,
        sha512="d" * 128,
    )

    finding = Finding(
        title="Test finding",
        description="Representative finding.",
        category="testing",
        severity=Severity.MEDIUM,
        confidence=80,
    )

    results = (
        _completed_result("strings"),
        _completed_result("entropy", findings=(finding,)),
        _completed_result("yara"),
        _completed_result("pe"),
        _completed_result("imports"),
        _completed_result("packer"),
    )

    with (
        patch(
            "packages.core.orchestrator.identify_file",
            return_value=file_type,
        ),
        patch(
            "packages.core.orchestrator.calculate_hashes",
            return_value=hashes,
        ),
        patch.object(
            AnalysisOrchestrator,
            "_run_analyzers",
            return_value=results,
        ),
    ):
        report = AnalysisOrchestrator(tmp_path / "rules").analyze(sample)

    assert report.original_name == "sample.exe"
    assert report.file_type.detected_family == "pe"
    assert len(report.analyzer_results) == 6
    assert report.completed_analyzers == 6
    assert report.failed_analyzers == 0
    assert report.findings == (finding,)
    assert len(report.analyzer_executions) == 6


def test_orchestrator_counts_failed_analyzers(tmp_path: Path) -> None:
    """Failed and partial analyzer results should be counted."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    file_type = FileTypeResult(
        file_name="sample.bin",
        extension=".bin",
        mime_type="application/octet-stream",
        magic_description="data",
        detected_family="unknown",
        extension_matches=None,
        is_executable=False,
        confidence=25,
        source_path=sample,
    )

    hashes = FileHashes(
        md5="a" * 32,
        sha1="b" * 40,
        sha256="c" * 64,
        sha512="d" * 128,
    )

    results = (
        _completed_result("strings"),
        AnalysisResult(
            analyzer="entropy",
            analyzer_version="0.1.0",
            status=AnalysisStatus.PARTIAL,
            duration_ms=1,
        ),
        AnalysisResult(
            analyzer="yara",
            analyzer_version="0.1.0",
            status=AnalysisStatus.FAILED,
            duration_ms=1,
        ),
    )

    with (
        patch(
            "packages.core.orchestrator.identify_file",
            return_value=file_type,
        ),
        patch(
            "packages.core.orchestrator.calculate_hashes",
            return_value=hashes,
        ),
        patch.object(
            AnalysisOrchestrator,
            "_run_analyzers",
            return_value=results,
        ),
    ):
        report = AnalysisOrchestrator(tmp_path / "rules").analyze(sample)

    assert report.completed_analyzers == 1
    assert report.failed_analyzers == 2


def test_orchestrator_rejects_missing_file(tmp_path: Path) -> None:
    """Missing samples should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        AnalysisOrchestrator().analyze(tmp_path / "missing.bin")


def test_orchestrator_rejects_directory(tmp_path: Path) -> None:
    """Directories should not be accepted as samples."""
    with pytest.raises(ValueError, match="regular file"):
        AnalysisOrchestrator().analyze(tmp_path)
