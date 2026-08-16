"""Tests for Astra PE fingerprint analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.fingerprints import FingerprintsAnalyzer
from packages.schemas import AnalysisStatus


def _mock_import(
    *,
    name: bytes | None = None,
    ordinal: int | None = None,
) -> MagicMock:
    """Create one mocked PE import entry."""
    imported = MagicMock()
    imported.name = name
    imported.ordinal = ordinal

    return imported


def _mock_descriptor(
    *,
    dll: bytes | None = b"kernel32.dll",
    imports: tuple[MagicMock, ...] = (),
) -> MagicMock:
    """Create one mocked import descriptor."""
    descriptor = MagicMock()
    descriptor.dll = dll
    descriptor.imports = list(imports)

    return descriptor


def _mock_pe(
    *,
    descriptors: tuple[MagicMock, ...] = (),
    imphash: str | None = "a" * 32,
) -> MagicMock:
    """Create a mocked PE object."""
    pe = MagicMock()
    pe.DIRECTORY_ENTRY_IMPORT = list(descriptors)
    pe.get_imphash.return_value = imphash

    return pe


def test_fingerprints_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = FingerprintsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_named_import_is_normalized(
    tmp_path: Path,
) -> None:
    """Named imports should be normalized correctly."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        dll=b"KERNEL32.DLL",
        imports=(
            _mock_import(
                name=b"CreateFileW",
            ),
        ),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["fingerprint_available"] is True
    assert result.data["import_library_count"] == 1
    assert result.data["import_count"] == 1
    assert result.data["named_import_count"] == 1
    assert result.data["ordinal_import_count"] == 0
    assert result.data["malformed_import_count"] == 0

    entry = result.data["libraries"][0]["imports"][0]

    assert entry["library"] == "KERNEL32.DLL"
    assert entry["symbol"] == "CreateFileW"
    assert entry["imported_by_name"] is True
    assert entry["imported_by_ordinal"] is False
    assert entry["normalized"] == "kernel32.createfilew"


def test_ordinal_import_is_normalized(
    tmp_path: Path,
) -> None:
    """Ordinal-only imports should be normalized."""
    sample = tmp_path / "ordinal.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        dll=b"comctl32.dll",
        imports=(
            _mock_import(
                name=None,
                ordinal=17,
            ),
        ),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["ordinal_import_count"] == 1
    assert result.data["named_import_count"] == 0

    entry = result.data["libraries"][0]["imports"][0]

    assert entry["symbol"] is None
    assert entry["ordinal"] == 17
    assert entry["normalized"] == "comctl32.ord17"


def test_multiple_libraries_are_counted(
    tmp_path: Path,
) -> None:
    """Multiple libraries should be aggregated."""
    sample = tmp_path / "multi.exe"
    sample.write_bytes(b"MZ")

    kernel32 = _mock_descriptor(
        dll=b"kernel32.dll",
        imports=(
            _mock_import(name=b"Sleep"),
            _mock_import(name=b"CreateFileW"),
        ),
    )

    user32 = _mock_descriptor(
        dll=b"user32.dll",
        imports=(_mock_import(name=b"MessageBoxW"),),
    )

    pe = _mock_pe(
        descriptors=(
            kernel32,
            user32,
        ),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["import_library_count"] == 2
    assert result.data["import_count"] == 3
    assert result.data["named_import_count"] == 3


def test_empty_library_name_falls_back_to_unknown(
    tmp_path: Path,
) -> None:
    """Missing library names should normalize safely."""
    sample = tmp_path / "unknown.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        dll=b"",
        imports=(_mock_import(name=b"Sleep"),),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["libraries"][0]["name"] == "unknown"


def test_malformed_import_is_counted(
    tmp_path: Path,
) -> None:
    """Imports without name or ordinal should be marked malformed."""
    sample = tmp_path / "malformed.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        imports=(
            _mock_import(
                name=None,
                ordinal=None,
            ),
        ),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_import_count"] == 1

    entry = result.data["libraries"][0]["imports"][0]

    assert entry["normalized"] == "kernel32.unknown"


def test_pefile_imphash_is_used(
    tmp_path: Path,
) -> None:
    """Canonical pefile ImpHash should be preferred."""
    sample = tmp_path / "imphash.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        imports=(_mock_import(name=b"Sleep"),),
    )

    expected = "1234567890abcdef1234567890abcdef"

    pe = _mock_pe(
        descriptors=(descriptor,),
        imphash=expected,
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["imphash"] == expected


def test_fallback_imphash_is_generated(
    tmp_path: Path,
) -> None:
    """A deterministic fallback hash should be generated."""
    sample = tmp_path / "fallback.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        imports=(_mock_import(name=b"Sleep"),),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
        imphash=None,
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["imphash"] is not None
    assert len(result.data["imphash"]) == 32


def test_no_imports_returns_unavailable_fingerprint(
    tmp_path: Path,
) -> None:
    """A PE without imports should return no fingerprint."""
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        descriptors=(),
        imphash=None,
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["fingerprint_available"] is False
    assert result.data["imphash"] is None
    assert result.data["fingerprint_source"] is None
    assert result.data["import_count"] == 0


def test_fingerprint_source_is_deterministic(
    tmp_path: Path,
) -> None:
    """Normalized fingerprint input should preserve deterministic order."""
    sample = tmp_path / "source.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        dll=b"kernel32.dll",
        imports=(
            _mock_import(name=b"Sleep"),
            _mock_import(name=b"CreateFileW"),
        ),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.data["fingerprint_source"] == ("kernel32.sleep,kernel32.createfilew")


def test_get_imphash_failure_uses_fallback(
    tmp_path: Path,
) -> None:
    """pefile ImpHash failures should not break analysis."""
    sample = tmp_path / "fallback-error.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        imports=(_mock_import(name=b"Sleep"),),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )
    pe.get_imphash.side_effect = RuntimeError("ImpHash failed")

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["imphash"] is not None
    assert len(result.data["imphash"]) == 32


def test_analyzer_produces_no_findings(
    tmp_path: Path,
) -> None:
    """Fingerprinting should not affect scoring by itself."""
    sample = tmp_path / "neutral.exe"
    sample.write_bytes(b"MZ")

    descriptor = _mock_descriptor(
        imports=(_mock_import(name=b"CreateRemoteThread"),),
    )

    pe = _mock_pe(
        descriptors=(descriptor,),
    )

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.findings == ()


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE samples should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should produce a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.fingerprints.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = FingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = FingerprintsAnalyzer()

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
    analyzer = FingerprintsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
