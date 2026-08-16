"""Tests for Astra ELF symbol, import, and export analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfsymbols import ELFSymbolsAnalyzer
from packages.schemas import (
    AnalysisStatus,
    ELFSymbolEntry,
)


def _mock_symbol(
    *,
    name: str,
    binding: str = "STB_GLOBAL",
    symbol_type: str = "STT_FUNC",
    visibility: str = "STV_DEFAULT",
    section_index: str | int = "SHN_UNDEF",
    value: int = 0,
    size: int = 0,
) -> MagicMock:
    """Create a minimal ELF symbol fixture."""
    symbol = MagicMock()

    symbol.name = name
    symbol.entry.st_info.bind = binding
    symbol.entry.st_info.type = symbol_type
    symbol.entry.st_other.visibility = visibility
    symbol.entry.st_shndx = section_index
    symbol.entry.st_value = value
    symbol.entry.st_size = size

    return symbol


def _mock_symbol_table(
    *,
    name: str,
    symbols: list[MagicMock],
) -> MagicMock:
    """Create a mocked ELF symbol-table section."""
    section = MagicMock()
    section.name = name
    section.iter_symbols.return_value = symbols

    return section


def _mock_elf(
    *,
    sections: list[object] | None = None,
    symtab: object | None = None,
) -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.iter_sections.return_value = sections if sections is not None else []

    elf.get_section_by_name.return_value = symtab

    return elf


def test_elfsymbols_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ELFSymbolsAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_imported_symbol_is_normalized(
    tmp_path: Path,
) -> None:
    """Undefined global symbols should be treated as imports."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="printf",
        section_index="SHN_UNDEF",
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["symbol_count"] == 1
    assert result.data["dynamic_symbol_count"] == 1
    assert result.data["import_count"] == 1

    normalized = result.data["symbols"][0]

    assert normalized["name"] == "printf"
    assert normalized["imported"] is True
    assert normalized["exported"] is False


def test_exported_symbol_is_normalized(
    tmp_path: Path,
) -> None:
    """Defined global symbols should be treated as exports."""
    sample = tmp_path / "export.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="run_payload",
        section_index=5,
        value=0x401000,
        size=32,
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_count"] == 1

    normalized = result.data["symbols"][0]

    assert normalized["imported"] is False
    assert normalized["exported"] is True
    assert normalized["value"] == 0x401000
    assert normalized["size"] == 32


def test_weak_symbol_is_counted(
    tmp_path: Path,
) -> None:
    """Weak ELF symbols should be counted."""
    sample = tmp_path / "weak.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="weak_func",
        binding="STB_WEAK",
        section_index=4,
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["weak_symbol_count"] == 1


def test_static_and_dynamic_tables_are_counted(
    tmp_path: Path,
) -> None:
    """Both .dynsym and .symtab should be counted independently."""
    sample = tmp_path / "tables.elf"
    sample.write_bytes(b"\x7fELF")

    dynamic_symbol = _mock_symbol(
        name="printf",
    )

    static_symbol = _mock_symbol(
        name="internal_main",
        section_index=7,
    )

    dynamic_table = _mock_symbol_table(
        name=".dynsym",
        symbols=[dynamic_symbol],
    )

    static_table = _mock_symbol_table(
        name=".symtab",
        symbols=[static_symbol],
    )

    elf = _mock_elf(
        sections=[
            dynamic_table,
            static_table,
        ],
        symtab=static_table,
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["symbol_count"] == 2
    assert result.data["dynamic_symbol_count"] == 1
    assert result.data["static_symbol_count"] == 1
    assert result.data["stripped"] is False


def test_stripped_binary_is_detected(
    tmp_path: Path,
) -> None:
    """Missing .symtab should indicate a stripped binary."""
    sample = tmp_path / "stripped.elf"
    sample.write_bytes(b"\x7fELF")

    dynamic_symbol = _mock_symbol(
        name="printf",
    )

    dynamic_table = _mock_symbol_table(
        name=".dynsym",
        symbols=[dynamic_symbol],
    )

    elf = _mock_elf(
        sections=[dynamic_table],
        symtab=None,
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["stripped"] is True


def test_suspicious_import_is_marked(
    tmp_path: Path,
) -> None:
    """Suspicious imported APIs should receive capability metadata."""
    sample = tmp_path / "suspicious.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="execve",
        section_index="SHN_UNDEF",
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_symbol_count"] == 1

    normalized = result.data["symbols"][0]

    assert normalized["suspicious"] is True
    assert normalized["suspicious_category"] == "process-execution"


def test_suspicious_export_is_not_marked(
    tmp_path: Path,
) -> None:
    """Defined symbols should not trigger imported-capability heuristics."""
    sample = tmp_path / "defined-system.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="system",
        section_index=5,
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_symbol_count"] == 0

    normalized = result.data["symbols"][0]

    assert normalized["exported"] is True
    assert normalized["suspicious"] is False
    assert normalized["suspicious_category"] is None


def test_symbol_version_suffix_is_normalized_for_heuristics(
    tmp_path: Path,
) -> None:
    """Versioned symbol names should still match capability rules."""
    sample = tmp_path / "versioned.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="system@GLIBC_2.2.5",
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_symbol_count"] == 1
    assert result.data["symbols"][0]["suspicious_category"] == "process-execution"


def test_findings_are_grouped_by_category(
    tmp_path: Path,
) -> None:
    """Multiple related APIs should produce one contextual finding."""
    sample = tmp_path / "network.elf"
    sample.write_bytes(b"\x7fELF")

    symbols = [
        _mock_symbol(
            name="socket",
        ),
        _mock_symbol(
            name="connect",
        ),
        _mock_symbol(
            name="bind",
        ),
    ]

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=symbols,
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_symbol_count"] == 3
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.category == "network-access"
    assert finding.title == "ELF network-access capability"
    assert len(finding.evidence) == 3


def test_multiple_categories_produce_multiple_findings(
    tmp_path: Path,
) -> None:
    """Unrelated capabilities should remain separate findings."""
    sample = tmp_path / "capabilities.elf"
    sample.write_bytes(b"\x7fELF")

    symbols = [
        _mock_symbol(
            name="socket",
        ),
        _mock_symbol(
            name="execve",
        ),
        _mock_symbol(
            name="dlopen",
        ),
    ]

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=symbols,
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert len(result.findings) == 3

    categories = {finding.category for finding in result.findings}

    assert categories == {
        "network-access",
        "process-execution",
        "dynamic-loading",
    }


def test_duplicate_symbol_names_are_counted(
    tmp_path: Path,
) -> None:
    """Repeated symbol names should be counted as duplicates."""
    sample = tmp_path / "duplicates.elf"
    sample.write_bytes(b"\x7fELF")

    symbols = [
        _mock_symbol(
            name="duplicate",
            section_index=1,
        ),
        _mock_symbol(
            name="duplicate",
            section_index=2,
        ),
        _mock_symbol(
            name="unique",
            section_index=3,
        ),
    ]

    table = _mock_symbol_table(
        name=".symtab",
        symbols=symbols,
    )

    elf = _mock_elf(
        sections=[table],
        symtab=table,
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["duplicate_symbol_count"] == 1


def test_empty_symbol_name_is_ignored(
    tmp_path: Path,
) -> None:
    """Anonymous symbol entries should not inflate symbol counts."""
    sample = tmp_path / "empty.elf"
    sample.write_bytes(b"\x7fELF")

    symbol = _mock_symbol(
        name="",
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[symbol],
    )

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["symbol_count"] == 0


def test_malformed_symbol_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed individual symbols should not abort the table."""
    sample = tmp_path / "malformed.elf"
    sample.write_bytes(b"\x7fELF")

    good = _mock_symbol(
        name="printf",
    )

    bad = _mock_symbol(
        name="broken",
    )

    table = _mock_symbol_table(
        name=".dynsym",
        symbols=[
            good,
            bad,
        ],
    )

    elf = _mock_elf(
        sections=[table],
    )

    good_normalized = ELFSymbolEntry(
        name="printf",
        value=0,
        size=0,
        binding="STB_GLOBAL",
        symbol_type="STT_FUNC",
        visibility="STV_DEFAULT",
        section_index="SHN_UNDEF",
        imported=True,
        exported=False,
        weak=False,
        suspicious=False,
        suspicious_category=None,
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._normalize_symbol",
            side_effect=[
                good_normalized,
                RuntimeError("broken symbol"),
            ],
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["symbol_count"] == 1
    assert result.data["malformed_symbol_count"] == 1


def test_symbol_table_iteration_failure_is_counted(
    tmp_path: Path,
) -> None:
    """Broken symbol tables should be recorded as malformed."""
    sample = tmp_path / "broken-table.elf"
    sample.write_bytes(b"\x7fELF")

    table = MagicMock()
    table.name = ".dynsym"
    table.iter_symbols.side_effect = RuntimeError("broken symbol table")

    elf = _mock_elf(
        sections=[table],
    )

    with (
        patch(
            "analyzers.elfsymbols.analyzer.SymbolTableSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfsymbols.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_symbol_count"] == 1


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid ELF parsing should return a failed result."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.elfsymbols.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfsymbols.analyzer._load_elf",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ELFSymbolsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing files should raise FileNotFoundError."""
    analyzer = ELFSymbolsAnalyzer()

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
    analyzer = ELFSymbolsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
