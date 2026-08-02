"""Tests for Astra suspicious import analysis."""

from pathlib import Path
from unittest.mock import patch

from analyzers.common import Analyzer
from analyzers.signatures import ImportAnalyzer
from packages.schemas import AnalysisResult, AnalysisStatus, Severity


def _pe_result_with_imports() -> AnalysisResult:
    """Return a representative PE result with suspicious imports."""
    return AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "imports": [
                {
                    "library": "KERNEL32.dll",
                    "function": "CreateRemoteThread",
                    "address": 0x1000,
                    "ordinal": None,
                },
                {
                    "library": "KERNEL32.dll",
                    "function": "VirtualAllocEx",
                    "address": 0x2000,
                    "ordinal": None,
                },
                {
                    "library": "ADVAPI32.dll",
                    "function": "RegSetValueExW",
                    "address": 0x3000,
                    "ordinal": None,
                },
                {
                    "library": "KERNEL32.dll",
                    "function": "CloseHandle",
                    "address": 0x4000,
                    "ordinal": None,
                },
            ]
        },
    )


def test_import_analyzer_contract() -> None:
    """The import analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ImportAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_suspicious_imports_are_classified(tmp_path: Path) -> None:
    """Known suspicious APIs should produce indicators and findings."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.signatures.imports.PEAnalyzer.analyze",
        return_value=_pe_result_with_imports(),
    ):
        result = ImportAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["total_imports"] == 4
    assert result.data["suspicious_imports"] == 3
    assert len(result.findings) == 3

    assert any(
        finding.category == "process-injection" and finding.severity is Severity.HIGH
        for finding in result.findings
    )

    assert any(finding.category == "registry-modification" for finding in result.findings)


def test_imports_are_grouped_by_behavior(tmp_path: Path) -> None:
    """Indicators should be grouped into analyst-friendly behaviors."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.signatures.imports.PEAnalyzer.analyze",
        return_value=_pe_result_with_imports(),
    ):
        result = ImportAnalyzer().analyze(sample)

    behaviors = result.data["behaviors"]

    process_injection = next(
        behavior for behavior in behaviors if behavior["category"] == "process-injection"
    )

    assert process_injection["count"] == 2
    assert process_injection["maximum_severity"] == "high"


def test_failed_pe_analysis_is_propagated(tmp_path: Path) -> None:
    """A failed PE parse should propagate through import analysis."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "analyzers.signatures.imports.PEAnalyzer.analyze",
        return_value=failed,
    ):
        result = ImportAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.findings == ()
