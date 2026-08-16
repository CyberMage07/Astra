"""Tests for Astra ELF relocation analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfrelocations import ELFRelocationsAnalyzer
from packages.schemas import AnalysisStatus


def _mock_symbol(
    *,
    name: str,
    section_index: str | int = "SHN_UNDEF",
) -> MagicMock:
    """Create a minimal ELF symbol."""
    symbol = MagicMock()
    symbol.name = name
    symbol.entry.st_shndx = section_index
    return symbol


def _mock_symbol_table(
    symbols: dict[int, MagicMock],
) -> MagicMock:
    """Create a minimal symbol-table fixture."""
    table = MagicMock()

    def get_symbol(index: int) -> MagicMock:
        return symbols[index]

    table.get_symbol.side_effect = get_symbol

    return table


def _mock_relocation(
    *,
    offset: int = 0x404000,
    relocation_type: int = 7,
    symbol_index: int = 1,
    addend: int | None = None,
) -> MagicMock:
    """Create one relocation fixture."""
    relocation = MagicMock()

    relocation.entry.r_offset = offset
    relocation.entry.r_info_type = relocation_type
    relocation.entry.r_info_sym = symbol_index

    if addend is not None:
        relocation.entry.r_addend = addend

    return relocation


def _mock_relocation_section(
    *,
    name: str = ".rela.dyn",
    section_type: str = "SHT_RELA",
    linked_symbol_table_index: int = 3,
    relocations: list[MagicMock] | None = None,
) -> MagicMock:
    """Create one relocation-section fixture."""
    section = MagicMock()

    section.name = name
    section.header = {
        "sh_type": section_type,
        "sh_link": linked_symbol_table_index,
    }

    section.iter_relocations.return_value = relocations if relocations is not None else []

    return section


def _mock_elf(
    *,
    sections: list[object] | None = None,
    machine: str = "EM_X86_64",
    linked_section: object | None = None,
) -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.header = {
        "e_machine": machine,
    }

    elf.iter_sections.return_value = sections if sections is not None else []

    elf.get_section.return_value = linked_section

    return elf


def test_elfrelocations_analyzer_contract() -> None:
    """Analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ELFRelocationsAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_no_relocations_returns_empty_result(
    tmp_path: Path,
) -> None:
    """ELF files without relocation sections should return empty data."""
    sample = tmp_path / "empty.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elfrelocations.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["relocation_sections_present"] is False

    assert result.data["relocation_count"] == 0
    assert result.data["rela_count"] == 0
    assert result.data["rel_count"] == 0


def test_rela_relocation_is_normalized(
    tmp_path: Path,
) -> None:
    """RELA entries should preserve addends."""
    sample = tmp_path / "rela.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=8,
        symbol_index=0,
        addend=-32,
    )

    section = _mock_relocation_section(
        name=".rela.dyn",
        relocations=[
            relocation,
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["rela_count"] == 1

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["relocation_type_name"] == "R_X86_64_RELATIVE"
    assert entry["addend"] == -32
    assert entry["has_symbol"] is False


def test_rel_relocation_has_no_addend(
    tmp_path: Path,
) -> None:
    """REL entries should not expose explicit addends."""
    sample = tmp_path / "rel.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=7,
        symbol_index=1,
    )

    section = _mock_relocation_section(
        name=".rel.plt",
        section_type="SHT_REL",
        relocations=[
            relocation,
        ],
    )

    symbol_table = _mock_symbol_table({1: _mock_symbol(name="printf")})

    elf = _mock_elf(
        sections=[section],
        linked_section=symbol_table,
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["rel_count"] == 1

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["addend"] is None


def test_imported_symbol_is_resolved(
    tmp_path: Path,
) -> None:
    """Relocations should resolve imported symbol metadata."""
    sample = tmp_path / "import.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=6,
        symbol_index=1,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    symbol_table = _mock_symbol_table(
        {
            1: _mock_symbol(
                name="puts",
                section_index="SHN_UNDEF",
            )
        }
    )

    elf = _mock_elf(
        sections=[section],
        linked_section=symbol_table,
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["symbol_name"] == "puts"
    assert entry["has_symbol"] is True
    assert entry["imported_symbol"] is True

    assert result.data["imported_symbol_relocation_count"] == 1


def test_defined_symbol_is_not_imported(
    tmp_path: Path,
) -> None:
    """Defined relocation symbols should not be classified as imports."""
    sample = tmp_path / "defined.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=1,
        symbol_index=2,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    symbol_table = _mock_symbol_table(
        {
            2: _mock_symbol(
                name="local_func",
                section_index=7,
            )
        }
    )

    elf = _mock_elf(
        sections=[section],
        linked_section=symbol_table,
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["symbol_name"] == "local_func"
    assert entry["imported_symbol"] is False


def test_jump_slot_is_plt_related(
    tmp_path: Path,
) -> None:
    """JUMP_SLOT relocations should be classified as PLT-related."""
    sample = tmp_path / "plt.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=7,
        symbol_index=1,
    )

    section = _mock_relocation_section(
        name=".rela.plt",
        relocations=[
            relocation,
        ],
    )

    symbol_table = _mock_symbol_table({1: _mock_symbol(name="printf")})

    elf = _mock_elf(
        sections=[section],
        linked_section=symbol_table,
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["relocation_type_name"] == "R_X86_64_JUMP_SLOT"
    assert entry["plt_related"] is True
    assert result.data["plt_relocation_count"] == 1


def test_glob_dat_is_got_related(
    tmp_path: Path,
) -> None:
    """GLOB_DAT should be recognized as GOT-related."""
    sample = tmp_path / "got.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=6,
        symbol_index=1,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    symbol_table = _mock_symbol_table({1: _mock_symbol(name="puts")})

    elf = _mock_elf(
        sections=[section],
        linked_section=symbol_table,
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["got_related"] is True
    assert result.data["got_relocation_count"] == 1


def test_unknown_relocation_type_is_preserved(
    tmp_path: Path,
) -> None:
    """Unknown relocation IDs should remain visible."""
    sample = tmp_path / "unknown.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=9999,
        symbol_index=0,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["relocation_type_name"] == "UNKNOWN_9999"


def test_aarch64_relocation_name_is_resolved(
    tmp_path: Path,
) -> None:
    """Architecture-specific relocation names should be normalized."""
    sample = tmp_path / "arm64.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=1026,
        symbol_index=0,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    elf = _mock_elf(
        sections=[section],
        machine="EM_AARCH64",
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    entry = result.data["sections"][0]["relocations"][0]

    assert entry["relocation_type_name"] == "R_AARCH64_JUMP_SLOT"


def test_multiple_relocation_types_are_collected(
    tmp_path: Path,
) -> None:
    """Summary should retain unique relocation type names."""
    sample = tmp_path / "types.elf"
    sample.write_bytes(b"\x7fELF")

    section = _mock_relocation_section(
        relocations=[
            _mock_relocation(
                relocation_type=6,
            ),
            _mock_relocation(
                relocation_type=7,
            ),
            _mock_relocation(
                relocation_type=8,
                symbol_index=0,
            ),
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert set(result.data["relocation_types"]) == {
        "R_X86_64_GLOB_DAT",
        "R_X86_64_JUMP_SLOT",
        "R_X86_64_RELATIVE",
    }


def test_malformed_relocation_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed individual relocations should not abort a section."""
    sample = tmp_path / "malformed.elf"
    sample.write_bytes(b"\x7fELF")

    good = _mock_relocation(
        relocation_type=8,
        symbol_index=0,
    )

    bad = MagicMock()
    bad.entry = None

    section = _mock_relocation_section(
        relocations=[
            good,
            bad,
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["relocation_count"] == 1

    assert result.data["malformed_relocation_count"] == 1


def test_broken_relocation_section_is_counted(
    tmp_path: Path,
) -> None:
    """A broken relocation table should remain recoverable."""
    sample = tmp_path / "broken-table.elf"
    sample.write_bytes(b"\x7fELF")

    section = _mock_relocation_section()

    section.iter_relocations.side_effect = RuntimeError("broken relocation section")

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["malformed_relocation_count"] == 1


def test_analyzer_produces_no_findings_for_normal_relocations(
    tmp_path: Path,
) -> None:
    """Normal ELF relocation mechanics should not generate findings."""
    sample = tmp_path / "normal.elf"
    sample.write_bytes(b"\x7fELF")

    relocation = _mock_relocation(
        relocation_type=7,
    )

    section = _mock_relocation_section(
        relocations=[
            relocation,
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfrelocations.analyzer.RelocationSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfrelocations.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.findings == ()


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid ELF parsing should fail cleanly."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.elfrelocations.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfrelocations.analyzer._load_elf",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ELFRelocationsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing files should raise FileNotFoundError."""
    analyzer = ELFRelocationsAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.elf")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted."""
    analyzer = ELFRelocationsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
