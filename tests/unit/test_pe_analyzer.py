"""Tests for Astra Windows PE analysis."""

from pathlib import Path

import pytest

from analyzers.common import Analyzer
from analyzers.pe import PEAnalyzer
from packages.schemas import AnalysisStatus


def test_pe_analyzer_contract() -> None:
    """The PE analyzer should satisfy Astra's analyzer protocol."""
    analyzer = PEAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_missing_pe_file_raises(tmp_path: Path) -> None:
    """A missing PE path should raise FileNotFoundError."""
    analyzer = PEAnalyzer()
    missing = tmp_path / "missing.exe"

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(missing)


def test_directory_is_rejected(tmp_path: Path) -> None:
    """A directory must not be accepted as a PE sample."""
    analyzer = PEAnalyzer()

    with pytest.raises(ValueError, match="regular file"):
        analyzer.analyze(tmp_path)


def test_invalid_pe_returns_failed_result(tmp_path: Path) -> None:
    """Malformed PE content should return a structured failed result."""
    analyzer = PEAnalyzer()
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"This is not a PE executable.")

    result = analyzer.analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.analyzer == "pe"
    assert result.errors
    assert result.errors[0].recoverable is False
