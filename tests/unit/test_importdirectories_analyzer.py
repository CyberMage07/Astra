"""Tests for Astra PE delay-import and bound-import analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.importdirectories import ImportDirectoriesAnalyzer
from packages.schemas import AnalysisStatus


def _mock_delay_import(
    *,
    name: bytes | None = None,
    ordinal: int | None = None,
    address: int = 0x140001000,
) -> MagicMock:
    """Create one mocked delayed import."""
    imported = MagicMock()
    imported.name = name
    imported.ordinal = ordinal
    imported.address = address

    return imported


def _mock_delay_descriptor(
    *,
    dll: bytes | None = b"kernel32.dll",
    imports: tuple[MagicMock, ...] = (),
) -> MagicMock:
    """Create one mocked delay-import descriptor."""
    descriptor = MagicMock()
    descriptor.dll = dll
    descriptor.imports = list(imports)

    return descriptor


def _mock_bound_descriptor(
    *,
    name: bytes | None = b"kernel32.dll",
    timestamp: int = 123456,
    forwarder_count: int = 0,
    structure_present: bool = True,
) -> MagicMock:
    """Create one mocked bound-import descriptor."""
    descriptor = MagicMock()
    descriptor.name = name

    if structure_present:
        descriptor.struct.TimeDateStamp = timestamp
        descriptor.struct.NumberOfModuleForwarderRefs = forwarder_count
    else:
        descriptor.struct = None

    return descriptor


def _mock_pe(
    *,
    delay_descriptors: tuple[MagicMock, ...] = (),
    bound_descriptors: tuple[MagicMock, ...] = (),
) -> MagicMock:
    """Create a mocked PE object with import directories."""
    pe = MagicMock()

    pe.DIRECTORY_ENTRY_DELAY_IMPORT = list(delay_descriptors)
    pe.DIRECTORY_ENTRY_BOUND_IMPORT = list(bound_descriptors)

    return pe


def test_importdirectories_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ImportDirectoriesAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_delay_or_bound_imports_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without these directories should return an empty result."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe()

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["delay_import_directory_present"] is False
    assert result.data["bound_import_directory_present"] is False
    assert result.data["delay_library_count"] == 0
    assert result.data["delay_import_count"] == 0
    assert result.data["bound_library_count"] == 0
    assert result.findings == ()


def test_named_delay_import_is_normalized(
    tmp_path: Path,
) -> None:
    """A named delay import should be normalized."""
    sample = tmp_path / "delay.exe"
    sample.write_bytes(b"MZ")

    imported = _mock_delay_import(
        name=b"Sleep",
        ordinal=None,
    )

    descriptor = _mock_delay_descriptor(
        dll=b"kernel32.dll",
        imports=(imported,),
    )

    pe = _mock_pe(
        delay_descriptors=(descriptor,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["delay_import_directory_present"] is True
    assert result.data["delay_library_count"] == 1
    assert result.data["delay_import_count"] == 1

    library = result.data["delay_libraries"][0]
    entry = library["imports"][0]

    assert library["library"] == "kernel32.dll"
    assert entry["name"] == "Sleep"
    assert entry["imported_by_name"] is True
    assert entry["imported_by_ordinal"] is False
    assert entry["suspicious"] is False


def test_ordinal_delay_import_is_normalized(
    tmp_path: Path,
) -> None:
    """An ordinal-only delay import should be normalized."""
    sample = tmp_path / "ordinal.exe"
    sample.write_bytes(b"MZ")

    imported = _mock_delay_import(
        name=None,
        ordinal=123,
    )

    descriptor = _mock_delay_descriptor(
        imports=(imported,),
    )

    pe = _mock_pe(
        delay_descriptors=(descriptor,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    entry = result.data["delay_libraries"][0]["imports"][0]

    assert entry["name"] is None
    assert entry["ordinal"] == 123
    assert entry["imported_by_name"] is False
    assert entry["imported_by_ordinal"] is True


def test_suspicious_delay_import_generates_finding(
    tmp_path: Path,
) -> None:
    """Suspicious delayed APIs should generate a finding."""
    sample = tmp_path / "suspicious.exe"
    sample.write_bytes(b"MZ")

    imported = _mock_delay_import(
        name=b"CreateRemoteThread",
    )

    descriptor = _mock_delay_descriptor(
        dll=b"kernel32.dll",
        imports=(imported,),
    )

    pe = _mock_pe(
        delay_descriptors=(descriptor,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["suspicious_delay_import_count"] == 1

    assert any(
        finding.title == "Suspicious delayed Windows API imports detected"
        for finding in result.findings
    )


def test_multiple_delay_libraries_are_counted(
    tmp_path: Path,
) -> None:
    """Multiple delayed-import libraries should be counted correctly."""
    sample = tmp_path / "multi.exe"
    sample.write_bytes(b"MZ")

    kernel32 = _mock_delay_descriptor(
        dll=b"kernel32.dll",
        imports=(
            _mock_delay_import(name=b"Sleep"),
            _mock_delay_import(name=b"VirtualAlloc"),
        ),
    )

    user32 = _mock_delay_descriptor(
        dll=b"user32.dll",
        imports=(_mock_delay_import(name=b"MessageBoxW"),),
    )

    pe = _mock_pe(
        delay_descriptors=(
            kernel32,
            user32,
        ),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["delay_library_count"] == 2
    assert result.data["delay_import_count"] == 3
    assert result.data["suspicious_delay_import_count"] == 1


def test_empty_delay_library_name_falls_back_to_unknown(
    tmp_path: Path,
) -> None:
    """Empty delay-import library names should normalize to unknown."""
    sample = tmp_path / "unknown-library.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_delay_descriptor(
        dll=b"",
        imports=(_mock_delay_import(name=b"Sleep"),),
    )

    pe = _mock_pe(
        delay_descriptors=(descriptor,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["delay_libraries"][0]["library"] == "unknown"


def test_bound_import_is_normalized(
    tmp_path: Path,
) -> None:
    """A valid bound-import descriptor should be normalized."""
    sample = tmp_path / "bound.exe"
    sample.write_bytes(b"MZ")

    bound = _mock_bound_descriptor(
        name=b"kernel32.dll",
        timestamp=123456,
        forwarder_count=2,
    )

    pe = _mock_pe(
        bound_descriptors=(bound,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["bound_import_directory_present"] is True
    assert result.data["bound_library_count"] == 1
    assert result.data["malformed_bound_import_count"] == 0

    entry = result.data["bound_imports"][0]

    assert entry["library"] == "kernel32.dll"
    assert entry["timestamp"] == 123456
    assert entry["forwarder_count"] == 2
    assert entry["malformed"] is False


def test_missing_bound_structure_is_malformed(
    tmp_path: Path,
) -> None:
    """A bound descriptor without a structure should be malformed."""
    sample = tmp_path / "malformed-bound.exe"
    sample.write_bytes(b"MZ")

    bound = _mock_bound_descriptor(
        structure_present=False,
    )

    pe = _mock_pe(
        bound_descriptors=(bound,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_bound_import_count"] == 1
    assert result.data["bound_imports"][0]["malformed"] is True

    assert any(
        finding.title == "Malformed PE bound-import descriptors detected"
        for finding in result.findings
    )


def test_negative_bound_values_are_sanitized_and_malformed(
    tmp_path: Path,
) -> None:
    """Negative bound metadata should be sanitized and marked malformed."""
    sample = tmp_path / "negative-bound.exe"
    sample.write_bytes(b"MZ")

    bound = _mock_bound_descriptor(
        timestamp=-1,
        forwarder_count=-2,
    )

    pe = _mock_pe(
        bound_descriptors=(bound,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    entry = result.data["bound_imports"][0]

    assert entry["timestamp"] == 0
    assert entry["forwarder_count"] == 0
    assert entry["malformed"] is True


def test_empty_bound_library_name_falls_back_to_unknown(
    tmp_path: Path,
) -> None:
    """Empty bound-import names should normalize to unknown."""
    sample = tmp_path / "unknown-bound.exe"
    sample.write_bytes(b"MZ")

    bound = _mock_bound_descriptor(
        name=b"",
    )

    pe = _mock_pe(
        bound_descriptors=(bound,),
    )

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["bound_imports"][0]["library"] == "unknown"


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.importdirectories.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

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
        "analyzers.importdirectories.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ImportDirectoriesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ImportDirectoriesAnalyzer()

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
    analyzer = ImportDirectoriesAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
