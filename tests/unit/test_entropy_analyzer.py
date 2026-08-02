"""Tests for Astra entropy analysis."""

from pathlib import Path

import pytest

from analyzers.common import Analyzer
from analyzers.entropy import (
    EntropyAnalyzer,
    calculate_entropy,
)
from packages.schemas import AnalysisStatus


def test_entropy_analyzer_contract(tmp_path: Path) -> None:
    """The entropy analyzer should satisfy Astra's analyzer protocol."""
    analyzer = EntropyAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("text") is True
    assert analyzer.supports("unsupported-family") is False


def test_calculate_entropy_empty_data() -> None:
    """Empty data should have zero entropy."""
    assert calculate_entropy(b"") == 0.0


def test_calculate_entropy_uniform_data() -> None:
    """Uniform byte data should have zero entropy."""
    assert calculate_entropy(b"A" * 1024) == 0.0


def test_calculate_entropy_balanced_data() -> None:
    """Balanced byte values should produce measurable entropy."""
    data = bytes(range(256))

    assert calculate_entropy(data) == pytest.approx(8.0)


def test_low_entropy_file(tmp_path: Path) -> None:
    """A repetitive file should produce no high-entropy findings."""
    sample = tmp_path / "low.bin"
    sample.write_bytes(b"A" * 8192)

    result = EntropyAnalyzer(block_size=4096).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overall_entropy"] == 0.0
    assert result.data["high_entropy_regions"] == 0
    assert result.findings == ()


def test_high_entropy_file(tmp_path: Path) -> None:
    """Dense byte distributions should produce entropy findings."""
    sample = tmp_path / "high.bin"
    sample.write_bytes(bytes(range(256)) * 32)

    result = EntropyAnalyzer(block_size=4096).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overall_entropy"] == pytest.approx(8.0)
    assert result.data["high_entropy_regions"] == 2
    assert result.findings
    assert any(finding.title == "High overall file entropy" for finding in result.findings)


def test_invalid_block_size_is_rejected() -> None:
    """Block size must be greater than zero."""
    with pytest.raises(ValueError, match="block_size"):
        EntropyAnalyzer(block_size=0)


def test_missing_file_raises(tmp_path: Path) -> None:
    """A missing sample should raise FileNotFoundError."""
    analyzer = EntropyAnalyzer()

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(tmp_path / "missing.bin")


def test_directory_is_rejected(tmp_path: Path) -> None:
    """Directories should not be accepted as samples."""
    analyzer = EntropyAnalyzer()

    with pytest.raises(ValueError, match="regular file"):
        analyzer.analyze(tmp_path)
