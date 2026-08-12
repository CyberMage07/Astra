"""Tests for Astra PE relocation analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.relocations import RelocationsAnalyzer
from packages.schemas import AnalysisStatus

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def _mock_section(
    *,
    name: bytes = b".text\x00\x00\x00",
    virtual_address: int = 0x1000,
    virtual_size: int = 0x2000,
    raw_size: int = 0x2000,
    executable: bool = True,
    writable: bool = False,
) -> MagicMock:
    """Create a representative PE section."""
    section = MagicMock()

    section.Name = name
    section.VirtualAddress = virtual_address
    section.Misc_VirtualSize = virtual_size
    section.SizeOfRawData = raw_size

    characteristics = 0

    if executable:
        characteristics |= IMAGE_SCN_MEM_EXECUTE

    if writable:
        characteristics |= IMAGE_SCN_MEM_WRITE

    section.Characteristics = characteristics

    return section


def _mock_relocation_entry(
    *,
    relocation_type: int = 10,
    rva: int = 0x1100,
) -> MagicMock:
    """Create one mocked relocation entry."""
    entry = MagicMock()
    entry.type = relocation_type
    entry.rva = rva

    return entry


def _mock_relocation_block(
    *,
    page_rva: int = 0x1000,
    block_size: int = 12,
    entries: tuple[MagicMock, ...] = (),
    structure_present: bool = True,
) -> MagicMock:
    """Create one mocked relocation block."""
    block = MagicMock()

    if structure_present:
        block.struct.VirtualAddress = page_rva
        block.struct.SizeOfBlock = block_size
    else:
        block.struct = None

    block.entries = list(entries)

    return block


def _mock_pe(
    *,
    blocks: tuple[MagicMock, ...] = (),
    sections: tuple[MagicMock, ...] | None = None,
    image_base: int = 0x140000000,
    size_of_image: int = 0x100000,
) -> MagicMock:
    """Create a mocked PE object with relocation metadata."""
    pe = MagicMock()

    pe.OPTIONAL_HEADER.ImageBase = image_base
    pe.OPTIONAL_HEADER.SizeOfImage = size_of_image

    pe.sections = list(sections if sections is not None else (_mock_section(),))

    pe.DIRECTORY_ENTRY_BASERELOC = list(blocks)

    return pe


def test_relocations_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = RelocationsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_relocations_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without relocation blocks should return an empty result."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe()

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["relocation_directory_present"] is False
    assert result.data["block_count"] == 0
    assert result.data["relocation_count"] == 0
    assert result.findings == ()


def test_valid_dir64_relocation_is_normalized(
    tmp_path: Path,
) -> None:
    """A valid DIR64 relocation should be normalized."""
    sample = tmp_path / "dir64.exe"
    sample.write_bytes(b"MZ")

    entry = _mock_relocation_entry(
        relocation_type=10,
        rva=0x1100,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["relocation_directory_present"] is True
    assert result.data["block_count"] == 1
    assert result.data["relocation_count"] == 1
    assert result.data["mapped_relocation_count"] == 1
    assert result.data["malformed_relocation_count"] == 0
    assert result.data["unknown_type_count"] == 0

    relocation = result.data["blocks"][0]["entries"][0]

    assert relocation["relocation_type"] == 10
    assert relocation["relocation_type_name"] == "DIR64"
    assert relocation["rva"] == 0x1100
    assert relocation["virtual_address"] == 0x140001100
    assert relocation["section_name"] == ".text"
    assert relocation["is_mapped"] is True
    assert relocation["is_executable"] is True
    assert relocation["malformed"] is False


def test_absolute_relocation_is_valid(
    tmp_path: Path,
) -> None:
    """ABSOLUTE relocation padding should not be treated as suspicious."""
    sample = tmp_path / "absolute.exe"
    sample.write_bytes(b"MZ")

    entry = _mock_relocation_entry(
        relocation_type=0,
        rva=0x1100,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["unknown_type_count"] == 0
    assert result.data["malformed_relocation_count"] == 0
    assert result.findings == ()


def test_writable_relocation_is_counted(
    tmp_path: Path,
) -> None:
    """Relocations targeting writable sections should be counted."""
    sample = tmp_path / "writable.exe"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".data\x00\x00\x00",
        executable=False,
        writable=True,
    )

    entry = _mock_relocation_entry(
        rva=0x1100,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
        sections=(section,),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["writable_relocation_count"] == 1
    assert result.data["executable_relocation_count"] == 0
    assert result.findings == ()


def test_unmapped_relocation_is_malformed(
    tmp_path: Path,
) -> None:
    """A relocation outside mapped sections should be malformed."""
    sample = tmp_path / "unmapped.exe"
    sample.write_bytes(b"MZ")

    entry = _mock_relocation_entry(
        relocation_type=10,
        rva=0x50000,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
        size_of_image=0x100000,
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_relocation_count"] == 1

    relocation = result.data["blocks"][0]["entries"][0]

    assert relocation["is_mapped"] is False
    assert relocation["malformed"] is True

    assert any(
        finding.title == "Malformed PE relocation entries detected" for finding in result.findings
    )


def test_out_of_image_relocation_is_malformed(
    tmp_path: Path,
) -> None:
    """An RVA outside SizeOfImage should be malformed."""
    sample = tmp_path / "outside.exe"
    sample.write_bytes(b"MZ")

    entry = _mock_relocation_entry(
        relocation_type=10,
        rva=0x200000,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
        size_of_image=0x100000,
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_relocation_count"] == 1


def test_unknown_relocation_type_generates_finding(
    tmp_path: Path,
) -> None:
    """Unknown relocation types should generate a finding."""
    sample = tmp_path / "unknown.exe"
    sample.write_bytes(b"MZ")

    entry = _mock_relocation_entry(
        relocation_type=15,
        rva=0x1100,
    )

    block = _mock_relocation_block(
        entries=(entry,),
    )

    pe = _mock_pe(
        blocks=(block,),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["unknown_type_count"] == 1
    assert "UNKNOWN_15" in result.data["relocation_types"]

    assert any(
        finding.title == "Unknown PE relocation types detected" for finding in result.findings
    )


def test_missing_block_structure_is_recorded_as_malformed(
    tmp_path: Path,
) -> None:
    """A relocation block without a structure should be malformed."""
    sample = tmp_path / "missing-struct.exe"
    sample.write_bytes(b"MZ")

    block = _mock_relocation_block(
        structure_present=False,
    )

    pe = _mock_pe(
        blocks=(block,),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_relocation_count"] == 1


def test_multiple_blocks_and_types_are_counted(
    tmp_path: Path,
) -> None:
    """Multiple relocation blocks and types should be aggregated."""
    sample = tmp_path / "multiple.exe"
    sample.write_bytes(b"MZ")

    block_one = _mock_relocation_block(
        page_rva=0x1000,
        entries=(
            _mock_relocation_entry(
                relocation_type=10,
                rva=0x1100,
            ),
            _mock_relocation_entry(
                relocation_type=0,
                rva=0x1200,
            ),
        ),
    )

    block_two = _mock_relocation_block(
        page_rva=0x2000,
        entries=(
            _mock_relocation_entry(
                relocation_type=3,
                rva=0x2100,
            ),
        ),
    )

    pe = _mock_pe(
        blocks=(
            block_one,
            block_two,
        ),
    )

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["block_count"] == 2
    assert result.data["relocation_count"] == 3
    assert result.data["relocation_types"] == [
        "ABSOLUTE",
        "DIR64",
        "HIGHLOW",
    ]


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.relocations.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = RelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = RelocationsAnalyzer()

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
    analyzer = RelocationsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
