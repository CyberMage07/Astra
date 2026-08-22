"""Tests for Astra ELF section entropy and layout analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfsections import ELFSectionsAnalyzer
from packages.schemas import AnalysisStatus


def _mock_elf(
    sections: list[MagicMock] | None = None,
) -> MagicMock:
    """Create a minimal mocked ELF object."""
    elf = MagicMock()

    elf.iter_sections.return_value = sections if sections is not None else []

    return elf


def _mock_section(
    *,
    name: str = ".text",
    section_type: str = "SHT_PROGBITS",
    address: int = 0x401000,
    offset: int = 0x100,
    size: int = 0x100,
    flags: int = 0x6,
    alignment: int = 16,
    data: bytes | None = None,
) -> MagicMock:
    """Create one mocked ELF section."""
    section = MagicMock()

    section.name = name

    section.header = {
        "sh_type": section_type,
        "sh_addr": address,
        "sh_offset": offset,
        "sh_size": size,
        "sh_flags": flags,
        "sh_addralign": alignment,
    }

    if data is None:
        section.data.return_value = b"A" * size
    else:
        section.data.return_value = data

    return section


def test_elfsections_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFSectionsAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )

    assert analyzer.supports("elf") is True

    assert analyzer.supports("pe") is False


def test_normal_section_is_normalized(
    tmp_path: Path,
) -> None:
    """A normal ELF section should be normalized correctly."""
    sample = tmp_path / "normal.elf"
    sample.write_bytes(b"\x00" * 4096)

    section = _mock_section(
        name=".text",
        flags=0x6,
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["section_count"] == 1

    normalized = result.data["sections"][0]

    assert normalized["name"] == ".text"

    assert normalized["allocatable"] is True

    assert normalized["executable"] is True

    assert normalized["writable"] is False

    assert normalized["rwx"] is False


def test_writable_section_is_counted(
    tmp_path: Path,
) -> None:
    """Writable ELF sections should be counted."""
    sample = tmp_path / "writable.elf"
    sample.write_bytes(b"\x00" * 4096)

    section = _mock_section(
        name=".data",
        flags=0x3,
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["writable_section_count"] == 1

    assert result.data["sections"][0]["writable"] is True


def test_rwx_section_generates_finding(
    tmp_path: Path,
) -> None:
    """Writable and executable sections should produce a finding."""
    sample = tmp_path / "rwx.elf"
    sample.write_bytes(b"\x00" * 4096)

    section = _mock_section(
        name=".text",
        flags=0x7,
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["rwx_section_count"] == 1

    assert any(
        finding.title == ("Writable and executable ELF sections detected")
        for finding in result.findings
    )


def test_high_entropy_executable_section_generates_finding(
    tmp_path: Path,
) -> None:
    """High-entropy executable data should be surfaced."""
    sample = tmp_path / "entropy.elf"
    sample.write_bytes(b"\x00" * 8192)

    high_entropy_data = bytes(range(256)) * 16

    section = _mock_section(
        name=".text",
        size=len(high_entropy_data),
        flags=0x6,
        data=high_entropy_data,
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["high_entropy_section_count"] == 1

    assert any(
        finding.title == ("High-entropy executable ELF sections detected")
        for finding in result.findings
    )


def test_suspicious_section_name_generates_finding(
    tmp_path: Path,
) -> None:
    """Packing-like section names should be detected."""
    sample = tmp_path / "packed.elf"
    sample.write_bytes(b"\x00" * 4096)

    section = _mock_section(
        name=".upx1",
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["suspicious_name_count"] == 1

    assert any(
        finding.title == ("Suspicious ELF section names detected") for finding in result.findings
    )


def test_sht_nobits_is_not_out_of_bounds(
    tmp_path: Path,
) -> None:
    """SHT_NOBITS sections should not be treated as file-backed."""
    sample = tmp_path / "bss.elf"
    sample.write_bytes(b"\x00" * 1024)

    section = _mock_section(
        name=".bss",
        section_type="SHT_NOBITS",
        offset=900,
        size=4096,
        flags=0x3,
        data=b"",
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["out_of_bounds_section_count"] == 0

    assert result.data["sections"][0]["out_of_bounds"] is False


def test_overlapping_file_backed_sections_are_detected(
    tmp_path: Path,
) -> None:
    """Overlapping file-backed sections should be marked."""
    sample = tmp_path / "overlap.elf"
    sample.write_bytes(b"\x00" * 4096)

    first = _mock_section(
        name=".first",
        offset=0x100,
        size=0x200,
    )

    second = _mock_section(
        name=".second",
        offset=0x200,
        size=0x200,
    )

    elf = _mock_elf(
        [
            first,
            second,
        ]
    )

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["overlapping_section_count"] == 2

    assert all(section["overlapping"] for section in result.data["sections"])

    assert any(
        finding.title == ("Abnormal ELF section layout detected") for finding in result.findings
    )


def test_out_of_bounds_section_is_detected(
    tmp_path: Path,
) -> None:
    """A genuine file-backed overflow should be detected."""
    sample = tmp_path / "bounds.elf"
    sample.write_bytes(b"\x00" * 1024)

    section = _mock_section(
        offset=900,
        size=512,
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["out_of_bounds_section_count"] == 1

    assert result.data["sections"][0]["out_of_bounds"] is True


def test_zero_sized_mapped_section_is_counted(
    tmp_path: Path,
) -> None:
    """Mapped zero-sized sections should be surfaced."""
    sample = tmp_path / "zero.elf"
    sample.write_bytes(b"\x00" * 1024)

    section = _mock_section(
        address=0x401000,
        size=0,
        flags=0x2,
        data=b"",
    )

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["zero_sized_mapped_count"] == 1


def test_unusually_large_section_table_is_detected(
    tmp_path: Path,
) -> None:
    """Very large section tables should be noted."""
    sample = tmp_path / "many.elf"
    sample.write_bytes(b"\x00" * 65536)

    sections = [
        _mock_section(
            name=f".section{index}",
            offset=(0x100 + index * 8),
            size=4,
        )
        for index in range(128)
    ]

    elf = _mock_elf(sections)

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["unusually_large_section_table"] is True

    assert any(
        finding.title == ("Unusually large ELF section table") for finding in result.findings
    )


def test_entropy_statistics_are_calculated(
    tmp_path: Path,
) -> None:
    """Aggregate entropy statistics should be populated."""
    sample = tmp_path / "entropy-stats.elf"
    sample.write_bytes(b"\x00" * 4096)

    first = _mock_section(
        name=".one",
        data=b"A" * 256,
        size=256,
    )

    second_data = bytes(range(256))

    second = _mock_section(
        name=".two",
        offset=0x400,
        size=256,
        data=second_data,
    )

    elf = _mock_elf(
        [
            first,
            second,
        ]
    )

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.data["maximum_entropy"] > 0.0

    assert result.data["average_entropy"] >= 0.0


def test_section_read_failure_is_safe(
    tmp_path: Path,
) -> None:
    """Unreadable section contents should not crash analysis."""
    sample = tmp_path / "read-error.elf"
    sample.write_bytes(b"\x00" * 4096)

    section = _mock_section()

    section.data.side_effect = RuntimeError("cannot read")

    elf = _mock_elf([section])

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["sections"][0]["entropy"] == 0.0


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected ELF parser errors should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL

    assert result.errors

    assert result.errors[0].recoverable is True


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid ELF parsing should produce a failed result."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.elfsections.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFSectionsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED

    assert result.errors

    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ELFSectionsAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.elf")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as samples."""
    analyzer = ELFSectionsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
