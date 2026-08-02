"""Tests for Astra metadata analysis."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.metadata import MetadataAnalyzer
from packages.schemas import AnalysisStatus


def _mock_pe(
    *,
    timestamp: int,
    version_entries: dict[bytes, bytes] | None = None,
) -> MagicMock:
    """Create a representative mocked PE object."""
    pe = MagicMock()
    pe.FILE_HEADER.TimeDateStamp = timestamp

    if version_entries is None:
        pe.FileInfo = []
        return pe

    string_table = MagicMock()
    string_table.entries = version_entries

    string_file_info = MagicMock()
    string_file_info.Key = b"StringFileInfo"
    string_file_info.StringTable = [string_table]

    pe.FileInfo = [[string_file_info]]
    return pe


def test_metadata_analyzer_contract() -> None:
    """The metadata analyzer should satisfy Astra's analyzer protocol."""
    analyzer = MetadataAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_version_information_is_normalized(
    tmp_path: Path,
) -> None:
    """PE version metadata should be extracted into normalized fields."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    timestamp = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())

    pe = _mock_pe(
        timestamp=timestamp,
        version_entries={
            b"CompanyName": b"Astra Labs",
            b"ProductName": b"Astra Sample",
            b"FileDescription": b"Representative executable",
            b"OriginalFilename": b"sample.exe",
            b"FileVersion": b"1.2.3.4",
        },
    )

    with patch(
        "analyzers.metadata.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = MetadataAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["company_name"] == "Astra Labs"
    assert result.data["product_name"] == "Astra Sample"
    assert result.data["file_description"] == ("Representative executable")
    assert result.data["original_filename"] == "sample.exe"
    assert result.data["file_version"] == "1.2.3.4"
    assert result.data["has_version_info"] is True
    assert result.data["future_timestamp"] is False
    assert result.data["suspicious_timestamp"] is False


def test_missing_version_info_generates_finding(
    tmp_path: Path,
) -> None:
    """Missing PE version metadata should generate an informational finding."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    timestamp = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())
    pe = _mock_pe(timestamp=timestamp)

    with patch(
        "analyzers.metadata.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = MetadataAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["has_version_info"] is False
    assert any(finding.title == "PE version information is missing" for finding in result.findings)


def test_future_timestamp_generates_finding(
    tmp_path: Path,
) -> None:
    """Future compile timestamps should be reported."""
    sample = tmp_path / "future.exe"
    sample.write_bytes(b"MZ")

    timestamp = int((datetime.now(UTC) + timedelta(days=7)).timestamp())
    pe = _mock_pe(timestamp=timestamp)

    with patch(
        "analyzers.metadata.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = MetadataAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["future_timestamp"] is True
    assert any(
        finding.title == "PE compile timestamp is in the future" for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should produce a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    result = MetadataAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing sample paths should raise FileNotFoundError."""
    analyzer = MetadataAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.exe")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")
