"""Tests for Astra PE export-table analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.exports import ExportsAnalyzer
from packages.schemas import AnalysisStatus

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _mock_section(
    *,
    name: bytes = b".text\x00\x00\x00",
    virtual_address: int = 0x1000,
    virtual_size: int = 0x1000,
    raw_size: int = 0x1000,
    executable: bool = True,
) -> MagicMock:
    """Create a representative PE section."""
    section = MagicMock()

    section.Name = name
    section.VirtualAddress = virtual_address
    section.Misc_VirtualSize = virtual_size
    section.SizeOfRawData = raw_size
    section.Characteristics = IMAGE_SCN_MEM_EXECUTE if executable else 0

    return section


def _mock_symbol(
    *,
    ordinal: int,
    address: int,
    name: bytes | None = None,
    forwarder: bytes | None = None,
) -> MagicMock:
    """Create one representative PE export symbol."""
    symbol = MagicMock()

    symbol.ordinal = ordinal
    symbol.address = address
    symbol.name = name
    symbol.forwarder = forwarder

    return symbol


def _mock_pe(
    *,
    symbols: tuple[MagicMock, ...] = (),
    module_name: bytes | None = b"sample.dll",
    export_present: bool = True,
    export_struct_present: bool = True,
    sections: tuple[MagicMock, ...] | None = None,
) -> MagicMock:
    """Create a mocked PE object with export metadata."""
    pe = MagicMock()

    pe.OPTIONAL_HEADER.ImageBase = 0x140000000

    pe.sections = list(sections if sections is not None else (_mock_section(),))

    if export_present:
        directory = MagicMock()
        directory.name = module_name
        directory.symbols = list(symbols)

        if export_struct_present:
            directory.struct = MagicMock()
        else:
            directory.struct = None

        pe.DIRECTORY_ENTRY_EXPORT = directory
    else:
        del pe.DIRECTORY_ENTRY_EXPORT

    return pe


def test_exports_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ExportsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_export_directory_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without exports should return an empty result."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        export_present=False,
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_directory_present"] is False
    assert result.data["export_count"] == 0
    assert result.data["named_export_count"] == 0
    assert result.data["ordinal_only_count"] == 0
    assert result.data["exports"] == []
    assert result.findings == ()


def test_named_executable_export_is_normalized(
    tmp_path: Path,
) -> None:
    """A named executable export should be normalized."""
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=1,
        address=0x1100,
        name=b"Initialize",
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_directory_present"] is True
    assert result.data["module_name"] == "sample.dll"
    assert result.data["export_count"] == 1
    assert result.data["named_export_count"] == 1
    assert result.data["ordinal_only_count"] == 0
    assert result.data["executable_export_count"] == 1
    assert result.data["unmapped_export_count"] == 0

    entry = result.data["exports"][0]

    assert entry["ordinal"] == 1
    assert entry["name"] == "Initialize"
    assert entry["rva"] == 0x1100
    assert entry["address"] == 0x140001100
    assert entry["section_name"] == ".text"
    assert entry["is_mapped"] is True
    assert entry["is_executable"] is True
    assert entry["is_forwarded"] is False
    assert entry["malformed"] is False


def test_ordinal_only_export_is_counted(
    tmp_path: Path,
) -> None:
    """An unnamed export should be counted as ordinal-only."""
    sample = tmp_path / "ordinal.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=7,
        address=0x1200,
        name=None,
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_count"] == 1
    assert result.data["named_export_count"] == 0
    assert result.data["ordinal_only_count"] == 1


def test_forwarded_export_is_normalized(
    tmp_path: Path,
) -> None:
    """A forwarded export should be recognized."""
    sample = tmp_path / "forward.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=1,
        address=0x5000,
        name=b"Sleep",
        forwarder=b"KERNEL32.Sleep",
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["forwarded_export_count"] == 1
    assert result.data["unmapped_export_count"] == 0

    entry = result.data["exports"][0]

    assert entry["is_forwarded"] is True
    assert entry["forwarder"] == "KERNEL32.Sleep"
    assert entry["is_mapped"] is True
    assert entry["is_executable"] is False
    assert entry["malformed"] is False


def test_suspicious_export_name_generates_finding(
    tmp_path: Path,
) -> None:
    """Suspicious export names should generate a finding."""
    sample = tmp_path / "payload.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=1,
        address=0x1100,
        name=b"InjectPayload",
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_name_count"] == 1

    assert any(
        finding.title == "Suspicious PE export names detected" for finding in result.findings
    )


def test_unmapped_export_is_malformed(
    tmp_path: Path,
) -> None:
    """An export RVA outside mapped sections should be malformed."""
    sample = tmp_path / "unmapped.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=1,
        address=0x900000,
        name=b"NormalExport",
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["unmapped_export_count"] == 1
    assert result.data["malformed_export_count"] == 1

    entry = result.data["exports"][0]

    assert entry["is_mapped"] is False
    assert entry["malformed"] is True

    assert any(
        finding.title == "Malformed or unmapped PE exports detected" for finding in result.findings
    )


def test_zero_ordinal_export_is_malformed(
    tmp_path: Path,
) -> None:
    """An invalid zero ordinal should mark an export malformed."""
    sample = tmp_path / "ordinal-zero.dll"
    sample.write_bytes(b"MZ")

    symbol = _mock_symbol(
        ordinal=0,
        address=0x1100,
        name=b"Example",
    )

    pe = _mock_pe(
        symbols=(symbol,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_export_count"] == 1
    assert result.data["exports"][0]["malformed"] is True


def test_duplicate_export_names_are_detected(
    tmp_path: Path,
) -> None:
    """Duplicate export names should be counted."""
    sample = tmp_path / "duplicate-name.dll"
    sample.write_bytes(b"MZ")

    symbols = (
        _mock_symbol(
            ordinal=1,
            address=0x1100,
            name=b"Initialize",
        ),
        _mock_symbol(
            ordinal=2,
            address=0x1200,
            name=b"Initialize",
        ),
    )

    pe = _mock_pe(
        symbols=symbols,
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["duplicate_name_count"] == 1

    assert any(
        finding.title == "Duplicate PE export records detected" for finding in result.findings
    )


def test_duplicate_export_ordinals_are_detected(
    tmp_path: Path,
) -> None:
    """Duplicate export ordinals should be counted."""
    sample = tmp_path / "duplicate-ordinal.dll"
    sample.write_bytes(b"MZ")

    symbols = (
        _mock_symbol(
            ordinal=1,
            address=0x1100,
            name=b"First",
        ),
        _mock_symbol(
            ordinal=1,
            address=0x1200,
            name=b"Second",
        ),
    )

    pe = _mock_pe(
        symbols=symbols,
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["duplicate_ordinal_count"] == 1


def test_non_executable_export_is_recorded(
    tmp_path: Path,
) -> None:
    """Exports in non-executable sections should be normalized."""
    sample = tmp_path / "data-export.dll"
    sample.write_bytes(b"MZ")

    section = _mock_section(
        name=b".data\x00\x00\x00",
        executable=False,
    )

    symbol = _mock_symbol(
        ordinal=1,
        address=0x1100,
        name=b"GlobalData",
    )

    pe = _mock_pe(
        symbols=(symbol,),
        sections=(section,),
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["executable_export_count"] == 0

    entry = result.data["exports"][0]

    assert entry["section_name"] == ".data"
    assert entry["is_mapped"] is True
    assert entry["is_executable"] is False
    assert entry["malformed"] is False


def test_missing_export_structure_is_recorded_as_malformed(
    tmp_path: Path,
) -> None:
    """A missing export structure should be represented as malformed."""
    sample = tmp_path / "missing-struct.dll"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        export_struct_present=False,
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_directory_present"] is True
    assert result.data["malformed_export_count"] == 1


def test_large_export_table_is_detected(
    tmp_path: Path,
) -> None:
    """Very large export tables should generate an info finding."""
    sample = tmp_path / "large.dll"
    sample.write_bytes(b"MZ")

    symbols = tuple(
        _mock_symbol(
            ordinal=index + 1,
            address=0x1100,
            name=f"Export{index}".encode(),
        )
        for index in range(4097)
    )

    pe = _mock_pe(
        symbols=symbols,
    )

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["export_count"] == 4097
    assert result.data["unusually_large_export_table"] is True

    assert any(
        finding.title == "Unusually large PE export table detected" for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.exports.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = ExportsAnalyzer().analyze(sample)

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
        "analyzers.exports.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ExportsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ExportsAnalyzer()

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
    analyzer = ExportsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
