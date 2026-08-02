"""Tests for Astra PE packer detection."""

from pathlib import Path
from unittest.mock import patch

from analyzers.common import Analyzer
from analyzers.packer import PackerAnalyzer
from packages.schemas import AnalysisResult, AnalysisStatus


def _pe_result(
    *,
    sections: list[dict[str, object]],
    import_count: int,
    overlay_size: int,
) -> AnalysisResult:
    """Return a representative normalized PE result."""
    imports = [
        {
            "library": "KERNEL32.dll",
            "function": f"Function{index}",
            "address": index,
            "ordinal": None,
        }
        for index in range(import_count)
    ]

    return AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "sections": sections,
            "imports": imports,
            "overlay_size": overlay_size,
        },
    )


def test_packer_analyzer_contract() -> None:
    """The packer analyzer should satisfy Astra's analyzer protocol."""
    analyzer = PackerAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_upx_sections_identify_upx(tmp_path: Path) -> None:
    """UPX section names should identify the likely packer."""
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ")

    pe_result = _pe_result(
        sections=[
            {
                "name": "UPX0",
                "entropy": 7.8,
                "executable": True,
                "writable": True,
            },
            {
                "name": "UPX1",
                "entropy": 7.6,
                "executable": True,
                "writable": False,
            },
        ],
        import_count=5,
        overlay_size=0,
    )

    with patch(
        "analyzers.packer.analyzer.PEAnalyzer.analyze",
        return_value=pe_result,
    ):
        result = PackerAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["is_likely_packed"] is True
    assert result.data["detected_packer"] == "UPX"
    assert result.data["confidence"] >= 90
    assert result.findings
    assert result.findings[0].attack_techniques == ("T1027",)


def test_heuristics_detect_unknown_packing(tmp_path: Path) -> None:
    """Multiple generic indicators should identify likely unknown packing."""
    sample = tmp_path / "unknown-packed.exe"
    sample.write_bytes(b"MZ")

    pe_result = _pe_result(
        sections=[
            {
                "name": ".mystery",
                "entropy": 7.9,
                "executable": True,
                "writable": True,
            },
            {
                "name": ".data",
                "entropy": 7.7,
                "executable": False,
                "writable": True,
            },
        ],
        import_count=3,
        overlay_size=2 * 1024 * 1024,
    )

    with patch(
        "analyzers.packer.analyzer.PEAnalyzer.analyze",
        return_value=pe_result,
    ):
        result = PackerAnalyzer().analyze(sample)

    assert result.data["is_likely_packed"] is True
    assert result.data["detected_packer"] is None
    assert result.data["high_entropy_sections"] == 2
    assert result.data["executable_writable_sections"] == 1
    assert result.findings


def test_clean_pe_is_not_marked_packed(tmp_path: Path) -> None:
    """A normal-looking PE should not be classified as packed."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    pe_result = _pe_result(
        sections=[
            {
                "name": ".text",
                "entropy": 6.2,
                "executable": True,
                "writable": False,
            },
            {
                "name": ".rdata",
                "entropy": 5.1,
                "executable": False,
                "writable": False,
            },
        ],
        import_count=100,
        overlay_size=0,
    )

    with patch(
        "analyzers.packer.analyzer.PEAnalyzer.analyze",
        return_value=pe_result,
    ):
        result = PackerAnalyzer().analyze(sample)

    assert result.data["is_likely_packed"] is False
    assert result.data["confidence"] < 60
    assert result.findings == ()


def test_failed_pe_analysis_is_propagated(tmp_path: Path) -> None:
    """A failed PE result should propagate through packer analysis."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="pe",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "analyzers.packer.analyzer.PEAnalyzer.analyze",
        return_value=failed,
    ):
        result = PackerAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.findings == ()
