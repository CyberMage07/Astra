"""Tests for Astra IOC extraction."""

from pathlib import Path
from unittest.mock import patch

from analyzers.common import Analyzer
from analyzers.ioc import IOCAnalyzer
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    IOCType,
)


def _strings_result() -> AnalysisResult:
    """Return representative extracted strings."""
    return AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "strings": [
                {
                    "value": "https://evil.example/payload.exe",
                    "offset": 100,
                    "encoding": "ascii",
                    "length": 32,
                },
                {
                    "value": "Contact admin@evil.example",
                    "offset": 200,
                    "encoding": "ascii",
                    "length": 26,
                },
                {
                    "value": "Connect to 192.168.1.25",
                    "offset": 300,
                    "encoding": "ascii",
                    "length": 23,
                },
                {
                    "value": (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
                    "offset": 400,
                    "encoding": "ascii",
                    "length": 52,
                },
                {
                    "value": r"powershell.exe -enc QUJDREVGR0g=",
                    "offset": 500,
                    "encoding": "ascii",
                    "length": 33,
                },
                {
                    "value": r"cmd.exe /c whoami",
                    "offset": 600,
                    "encoding": "ascii",
                    "length": 17,
                },
            ],
            "total_count": 6,
            "truncated": False,
            "minimum_length": 4,
        },
    )


def test_ioc_analyzer_contract() -> None:
    """The IOC analyzer should satisfy Astra's analyzer protocol."""
    analyzer = IOCAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("text") is True
    assert analyzer.supports("unsupported-family") is False


def test_iocs_are_extracted_and_normalized(tmp_path: Path) -> None:
    """Known IOC patterns should be extracted and normalized."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    with patch(
        "analyzers.ioc.analyzer.StringsAnalyzer.analyze",
        return_value=_strings_result(),
    ):
        result = IOCAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["unique_indicators"] > 0
    assert result.findings

    indicator_types = {
        IOCType(indicator["indicator_type"]) for indicator in result.data["indicators"]
    }

    assert IOCType.URL in indicator_types
    assert IOCType.DOMAIN in indicator_types
    assert IOCType.IPV4 in indicator_types
    assert IOCType.EMAIL in indicator_types
    assert IOCType.REGISTRY_PATH in indicator_types
    assert IOCType.POWERSHELL in indicator_types
    assert IOCType.CMD in indicator_types


def test_duplicate_iocs_are_deduplicated(tmp_path: Path) -> None:
    """Repeated IOC values should appear only once per type."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    strings_result = AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "strings": [
                {
                    "value": "https://evil.example/path",
                    "offset": 10,
                    "encoding": "ascii",
                    "length": 25,
                },
                {
                    "value": "HTTPS://EVIL.EXAMPLE/path",
                    "offset": 50,
                    "encoding": "ascii",
                    "length": 25,
                },
            ],
            "total_count": 2,
            "truncated": False,
            "minimum_length": 4,
        },
    )

    with patch(
        "analyzers.ioc.analyzer.StringsAnalyzer.analyze",
        return_value=strings_result,
    ):
        result = IOCAnalyzer().analyze(sample)

    urls = [
        indicator for indicator in result.data["indicators"] if indicator["indicator_type"] == "url"
    ]

    assert len(urls) == 1


def test_invalid_ipv4_is_ignored(tmp_path: Path) -> None:
    """Invalid IPv4 candidates should not be returned."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    strings_result = AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "strings": [
                {
                    "value": "999.999.999.999",
                    "offset": 10,
                    "encoding": "ascii",
                    "length": 15,
                }
            ],
            "total_count": 1,
            "truncated": False,
            "minimum_length": 4,
        },
    )

    with patch(
        "analyzers.ioc.analyzer.StringsAnalyzer.analyze",
        return_value=strings_result,
    ):
        result = IOCAnalyzer().analyze(sample)

    assert all(indicator["indicator_type"] != "ipv4" for indicator in result.data["indicators"])


def test_failed_strings_analysis_is_propagated(tmp_path: Path) -> None:
    """A failed strings result should propagate through IOC analysis."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    failed = AnalysisResult(
        analyzer="strings",
        analyzer_version="0.1.0",
        status=AnalysisStatus.PARTIAL,
        duration_ms=1,
    )

    with patch(
        "analyzers.ioc.analyzer.StringsAnalyzer.analyze",
        return_value=failed,
    ):
        result = IOCAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.findings == ()
