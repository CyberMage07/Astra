"""Tests for Astra YARA analysis."""

from pathlib import Path

import pytest

from analyzers.common import Analyzer
from analyzers.yara import YaraAnalyzer
from packages.schemas import AnalysisStatus


def _write_rule(rule_path: Path) -> None:
    """Create a harmless YARA test rule."""
    rule_path.write_text(
        """
rule Astra_Test_String
{
    meta:
        severity = "info"
        category = "testing"

    strings:
        $marker = "ASTRA_YARA_TEST_MARKER" ascii wide

    condition:
        $marker
}
""".strip(),
        encoding="utf-8",
    )


def test_yara_analyzer_contract(tmp_path: Path) -> None:
    """The YARA analyzer should satisfy Astra's analyzer protocol."""
    analyzer = YaraAnalyzer(tmp_path)

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("text") is True


def test_yara_match_is_normalized(tmp_path: Path) -> None:
    """Matching rules should produce normalized YARA data."""
    rules_root = tmp_path / "rules"
    rules_root.mkdir()
    _write_rule(rules_root / "test.yar")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"prefix ASTRA_YARA_TEST_MARKER suffix")

    result = YaraAnalyzer(rules_root).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["match_count"] == 1

    match = result.data["matches"][0]
    assert match["rule"] == "Astra_Test_String"
    assert match["namespace"] == "test"
    assert match["metadata"]["severity"] == "info"
    assert match["strings"][0]["identifier"] == "$marker"

    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.title == "YARA rule matched: Astra_Test_String"
    assert finding.category == "testing"
    assert finding.severity.value == "info"
    assert finding.confidence == 90
    assert finding.evidence[0].kind == "yara-string"
    assert finding.evidence[0].metadata["identifier"] == "$marker"


def test_yara_no_match_returns_completed(tmp_path: Path) -> None:
    """A valid scan with no matches should still complete successfully."""
    rules_root = tmp_path / "rules"
    rules_root.mkdir()
    _write_rule(rules_root / "test.yar")

    sample = tmp_path / "clean.bin"
    sample.write_bytes(b"nothing suspicious here")

    result = YaraAnalyzer(rules_root).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["match_count"] == 0
    assert result.data["matches"] == []


def test_missing_sample_raises(tmp_path: Path) -> None:
    """A missing sample path should raise FileNotFoundError."""
    analyzer = YaraAnalyzer(tmp_path)

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(tmp_path / "missing.bin")


def test_missing_rules_root_returns_partial_or_raises(tmp_path: Path) -> None:
    """A missing rule directory should be reported consistently."""
    analyzer = YaraAnalyzer(tmp_path / "missing-rules")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    with pytest.raises(FileNotFoundError):
        analyzer.analyze(sample)
