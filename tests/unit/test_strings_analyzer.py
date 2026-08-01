"""Tests for Astra string extraction."""

from pathlib import Path

import pytest

from analyzers.common import Analyzer
from analyzers.strings import StringsAnalyzer
from packages.schemas import AnalysisStatus


def test_strings_analyzer_contract() -> None:
    """The strings analyzer should satisfy Astra's analyzer protocol."""
    analyzer = StringsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("text") is True
    assert analyzer.supports("image") is False


def test_extracts_ascii_and_utf16_strings(tmp_path: Path) -> None:
    """ASCII and UTF-16 strings should be extracted with metadata."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(
        b"\x00\x01HelloAstra\x00"
        + "PowerShell".encode("utf-16-le")
        + b"\x00\xff"
        + "Network".encode("utf-16-be")
    )

    result = StringsAnalyzer(minimum_length=4).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    strings = result.data["strings"]
    values = {entry["value"] for entry in strings}

    assert "HelloAstra" in values
    assert "PowerShell" in values
    assert "Network" in values
    assert result.data["total_count"] >= 3
    assert result.data["truncated"] is False


def test_results_are_sorted_by_offset(tmp_path: Path) -> None:
    """Extracted strings should be ordered by their file offsets."""
    sample = tmp_path / "ordered.bin"
    sample.write_bytes(b"First\x00Second\x00Third")

    result = StringsAnalyzer().analyze(sample)

    offsets = [entry["offset"] for entry in result.data["strings"]]

    assert offsets == sorted(offsets)


def test_result_limit_sets_truncated_flag(tmp_path: Path) -> None:
    """Results beyond the configured limit should be truncated."""
    sample = tmp_path / "many.bin"
    sample.write_bytes(b"One1\x00Two2\x00Three3\x00")

    result = StringsAnalyzer(maximum_results=2).analyze(sample)

    assert len(result.data["strings"]) == 2
    assert result.data["total_count"] == 3
    assert result.data["truncated"] is True


def test_invalid_configuration_is_rejected() -> None:
    """Invalid extraction limits should raise ValueError."""
    with pytest.raises(ValueError, match="minimum_length"):
        StringsAnalyzer(minimum_length=0)

    with pytest.raises(ValueError, match="maximum_results"):
        StringsAnalyzer(maximum_results=0)


def test_missing_file_raises(tmp_path: Path) -> None:
    """Missing sample files should raise FileNotFoundError."""
    analyzer = StringsAnalyzer()

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(tmp_path / "missing.bin")


def test_directory_is_rejected(tmp_path: Path) -> None:
    """Directories should not be accepted as samples."""
    analyzer = StringsAnalyzer()

    with pytest.raises(ValueError, match="regular file"):
        analyzer.analyze(tmp_path)
