"""Tests for Astra analyzer contracts."""

from pathlib import Path

from analyzers.common import Analyzer
from packages.schemas import AnalysisResult, AnalysisStatus


class ExampleAnalyzer:
    """Minimal analyzer used to validate the protocol."""

    name = "example"
    version = "0.1.0"
    supported_families = frozenset({"text"})

    def supports(self, family: str) -> bool:
        """Return whether the family is supported."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Return a normalized example result."""
        return AnalysisResult(
            analyzer=self.name,
            analyzer_version=self.version,
            status=AnalysisStatus.COMPLETED,
            duration_ms=0,
            data={"sample": str(sample_path)},
        )


def test_analyzer_protocol() -> None:
    """A conforming analyzer should satisfy the runtime protocol."""
    analyzer = ExampleAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("text") is True
    assert analyzer.supports("pe") is False


def test_analyzer_returns_normalized_result(tmp_path: Path) -> None:
    """A conforming analyzer should return AnalysisResult."""
    analyzer = ExampleAnalyzer()
    sample = tmp_path / "sample.txt"
    sample.write_text("Astra", encoding="utf-8")

    result = analyzer.analyze(sample)

    assert isinstance(result, AnalysisResult)
    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["sample"] == str(sample)
