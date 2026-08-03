"""Tests for Astra PE section analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.sections import SectionsAnalyzer
from packages.schemas import AnalysisStatus


def _mock_section(
    *,
    name: bytes,
    virtual_address: int = 0x1000,
    virtual_size: int = 0x1000,
    raw_offset: int = 0x400,
    raw_size: int = 0x1000,
    characteristics: int = 0x40000000,
    entropy: float = 5.0,
) -> MagicMock:
    """Create a representative mocked PE section."""
    section = MagicMock()
    section.Name = name
    section.VirtualAddress = virtual_address
    section.Misc_VirtualSize = virtual_size
    section.PointerToRawData = raw_offset
    section.SizeOfRawData = raw_size
    section.Characteristics = characteristics
    section.get_entropy.return_value = entropy

    return section


def _mock_pe(
    sections: list[MagicMock],
) -> MagicMock:
    """Create a mocked PE containing supplied sections."""
    pe = MagicMock()
    pe.sections = sections

    return pe


def test_sections_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = SectionsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_clean_sections_are_normalized(
    tmp_path: Path,
) -> None:
    """Normal PE sections should be returned without findings."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    text_section = _mock_section(
        name=b".text\x00\x00\x00",
        characteristics=0x60000000,
        entropy=6.2,
    )

    data_section = _mock_section(
        name=b".data\x00\x00\x00",
        virtual_address=0x2000,
        raw_offset=0x1400,
        characteristics=0xC0000000,
        entropy=4.1,
    )

    pe = _mock_pe(
        [
            text_section,
            data_section,
        ]
    )

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["section_count"] == 2
    assert result.data["executable_sections"] == 1
    assert result.data["writable_sections"] == 1
    assert result.data["rwx_sections"] == 0
    assert result.data["high_entropy_sections"] == 0
    assert result.findings == ()

    text = result.data["sections"][0]

    assert text["name"] == ".text"
    assert text["readable"] is True
    assert text["writable"] is False
    assert text["executable"] is True


def test_rwx_and_high_entropy_section_generates_findings(
    tmp_path: Path,
) -> None:
    """An RWX high-entropy section should produce findings."""
    sample = tmp_path / "rwx.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".evil\x00\x00\x00",
        characteristics=0xE0000000,
        entropy=7.8,
    )

    pe = _mock_pe([section])

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["high_entropy_sections"] == 1
    assert result.data["rwx_sections"] == 1
    assert result.data["wx_sections"] == 1

    titles = {finding.title for finding in result.findings}

    assert "High-entropy PE sections detected" in titles
    assert "RWX PE sections detected" in titles


def test_suspicious_packer_section_is_detected(
    tmp_path: Path,
) -> None:
    """Known packer section names should be identified."""
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b"UPX0\x00\x00\x00\x00",
        characteristics=0x60000000,
        entropy=7.9,
    )

    pe = _mock_pe([section])

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_name_sections"] == 1
    assert result.data["sections"][0]["is_suspicious_name"] is True

    assert any(
        finding.title == "Suspicious PE section names detected" for finding in result.findings
    )


def test_executable_resource_section_is_detected(
    tmp_path: Path,
) -> None:
    """Executable resource sections should produce a finding."""
    sample = tmp_path / "resource.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".rsrc\x00\x00\x00",
        characteristics=0x60000000,
        entropy=5.0,
    )

    pe = _mock_pe([section])

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["executable_resource_sections"] == 1
    assert result.data["sections"][0]["is_executable_resource"] is True

    assert any(
        finding.title == "Executable resource section detected" for finding in result.findings
    )


def test_virtual_raw_size_anomaly_is_detected(
    tmp_path: Path,
) -> None:
    """Large virtual-to-raw size differences should be detected."""
    sample = tmp_path / "anomaly.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".ndata\x00\x00",
        virtual_size=0x5000,
        raw_size=0x100,
        characteristics=0xE0000000,
        entropy=0.0,
    )

    pe = _mock_pe([section])

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["virtual_raw_anomalies"] == 1
    assert result.data["sections"][0]["has_virtual_raw_anomaly"] is True

    assert any(finding.title == "PE section size anomalies detected" for finding in result.findings)


def test_empty_executable_section_is_detected(
    tmp_path: Path,
) -> None:
    """Executable virtual sections without raw data should be detected."""
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".empty\x00\x00",
        virtual_size=0x2000,
        raw_size=0,
        characteristics=0x60000000,
        entropy=0.0,
    )

    pe = _mock_pe([section])

    with patch(
        "analyzers.sections.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["empty_executable_sections"] == 1
    assert result.data["virtual_raw_anomalies"] == 1

    titles = {finding.title for finding in result.findings}

    assert "Empty executable PE sections detected" in titles
    assert "PE section size anomalies detected" in titles


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE input should return a failed analysis result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    result = SectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = SectionsAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.exe")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as samples."""
    analyzer = SectionsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
