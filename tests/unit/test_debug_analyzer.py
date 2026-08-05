"""Tests for Astra PE debug-directory analysis."""

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.debug import DebugDirectoryAnalyzer
from packages.schemas import AnalysisStatus

IMAGE_DEBUG_TYPE_CODEVIEW = 2
IMAGE_DEBUG_TYPE_POGO = 13
IMAGE_DEBUG_TYPE_REPRO = 16


def _mock_debug_entry(
    *,
    debug_type: int,
    pointer_to_raw_data: int,
    size_of_data: int,
    address_of_raw_data: int = 0x2000,
    timestamp: int = 0,
    major_version: int = 0,
    minor_version: int = 0,
) -> MagicMock:
    """Create one mocked PE debug-directory entry."""
    entry = MagicMock()

    entry.struct.Type = debug_type
    entry.struct.TimeDateStamp = timestamp
    entry.struct.MajorVersion = major_version
    entry.struct.MinorVersion = minor_version
    entry.struct.SizeOfData = size_of_data
    entry.struct.AddressOfRawData = address_of_raw_data
    entry.struct.PointerToRawData = pointer_to_raw_data

    return entry


def _mock_pe(
    entries: tuple[MagicMock, ...],
) -> MagicMock:
    """Create a mocked PE object with debug entries."""
    pe = MagicMock()
    pe.DIRECTORY_ENTRY_DEBUG = list(entries)

    return pe


def _build_rsds_payload(
    *,
    pdb_path: str,
    pdb_guid: uuid.UUID | None = None,
    age: int = 1,
) -> bytes:
    """Build one valid RSDS CodeView payload."""
    guid = pdb_guid or uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")

    return (
        b"RSDS"
        + guid.bytes_le
        + age.to_bytes(
            4,
            byteorder="little",
        )
        + pdb_path.encode("utf-8")
        + b"\x00"
    )


def _build_nb10_payload(
    *,
    pdb_path: str,
    age: int = 2,
    timestamp: int = 0x12345678,
) -> bytes:
    """Build one valid NB10 CodeView payload."""
    return (
        b"NB10"
        + (0).to_bytes(
            4,
            byteorder="little",
        )
        + timestamp.to_bytes(
            4,
            byteorder="little",
        )
        + age.to_bytes(
            4,
            byteorder="little",
        )
        + pdb_path.encode("utf-8")
        + b"\x00"
    )


def test_debug_analyzer_contract() -> None:
    """The debug analyzer should satisfy Astra's analyzer protocol."""
    analyzer = DebugDirectoryAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_debug_directory_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without debug entries should return an empty result."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(())

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["debug_directory_present"] is False
    assert result.data["entry_count"] == 0
    assert result.data["codeview_entry_count"] == 0
    assert result.data["reproducible_entry_count"] == 0
    assert result.data["pdb_path_count"] == 0
    assert result.data["entries"] == []
    assert result.findings == ()


def test_valid_rsds_entry_is_normalized(
    tmp_path: Path,
) -> None:
    """A valid RSDS record should expose its GUID, age, and PDB path."""
    sample = tmp_path / "rsds.exe"

    pdb_path = r"C:\build\project\release\sample.pdb"
    payload = _build_rsds_payload(
        pdb_path=pdb_path,
        age=3,
    )

    pointer = 0x40
    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["debug_directory_present"] is True
    assert result.data["entry_count"] == 1
    assert result.data["codeview_entry_count"] == 1
    assert result.data["pdb_path_count"] == 1
    assert result.data["absolute_path_count"] == 1
    assert result.data["malformed_entries"] == 0

    entry = result.data["entries"][0]

    assert entry["debug_type"] == IMAGE_DEBUG_TYPE_CODEVIEW
    assert entry["debug_type_name"] == "CODEVIEW"
    assert entry["signature"] == "RSDS"
    assert entry["pdb_guid"] == ("00112233-4455-6677-8899-aabbccddeeff")
    assert entry["pdb_age"] == 3
    assert entry["pdb_path"] == pdb_path
    assert entry["malformed"] is False


def test_valid_nb10_entry_is_normalized(
    tmp_path: Path,
) -> None:
    """A valid NB10 record should expose its age and PDB path."""
    sample = tmp_path / "nb10.exe"

    pdb_path = r"C:\build\legacy\sample.pdb"
    payload = _build_nb10_payload(
        pdb_path=pdb_path,
        age=7,
    )

    pointer = 0x50
    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["codeview_entry_count"] == 1

    entry = result.data["entries"][0]

    assert entry["signature"] == "NB10"
    assert entry["pdb_guid"] is None
    assert entry["pdb_age"] == 7
    assert entry["pdb_path"] == pdb_path
    assert entry["malformed"] is False


def test_username_in_pdb_path_generates_finding(
    tmp_path: Path,
) -> None:
    """A PDB path containing a username should generate a finding."""
    sample = tmp_path / "username.exe"

    pdb_path = r"C:\Users\alice\Desktop\project\payload.pdb"
    payload = _build_rsds_payload(
        pdb_path=pdb_path,
    )

    pointer = 0x40
    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["username_path_count"] == 1
    assert result.data["absolute_path_count"] == 1

    assert any(
        finding.title == "PDB path exposes development username" for finding in result.findings
    )


def test_network_pdb_path_generates_finding(
    tmp_path: Path,
) -> None:
    """A UNC PDB path should generate a network-share finding."""
    sample = tmp_path / "network.exe"

    pdb_path = r"\\build-server\symbols\project\payload.pdb"
    payload = _build_rsds_payload(
        pdb_path=pdb_path,
    )

    pointer = 0x40
    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["network_path_count"] == 1

    assert any(
        finding.title == "PDB path references a network share" for finding in result.findings
    )


def test_truncated_codeview_entry_is_malformed(
    tmp_path: Path,
) -> None:
    """A truncated CodeView record should be marked malformed."""
    sample = tmp_path / "truncated.exe"

    payload = b"RSDS" + b"\x00" * 4
    pointer = 0x30

    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_entries"] == 1
    assert result.data["entries"][0]["malformed"] is True

    assert any(
        finding.title == "Malformed PE debug-directory entries detected"
        for finding in result.findings
    )


def test_out_of_bounds_payload_is_malformed(
    tmp_path: Path,
) -> None:
    """A debug payload outside the file should be malformed."""
    sample = tmp_path / "out-of-bounds.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 30)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=0x1000,
        size_of_data=128,
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_entries"] == 1
    assert result.data["entries"][0]["malformed"] is True


def test_reproducible_entry_is_counted(
    tmp_path: Path,
) -> None:
    """A reproducible-build debug entry should be counted."""
    sample = tmp_path / "repro.exe"

    payload = b"\x11\x22\x33\x44"
    pointer = 0x20

    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_REPRO,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["entry_count"] == 1
    assert result.data["reproducible_entry_count"] == 1
    assert result.data["entries"][0]["debug_type_name"] == "REPRO"
    assert result.data["entries"][0]["malformed"] is False


def test_pogo_entry_is_normalized_without_finding(
    tmp_path: Path,
) -> None:
    """A valid POGO debug entry should not be treated as suspicious."""
    sample = tmp_path / "pogo.exe"

    payload = b"PGU\x00" + b"\x00" * 12
    pointer = 0x20

    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_POGO,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["entry_count"] == 1
    assert result.data["entries"][0]["debug_type_name"] == "POGO"
    assert result.data["malformed_entries"] == 0
    assert result.findings == ()


def test_unknown_codeview_signature_is_malformed(
    tmp_path: Path,
) -> None:
    """An unknown CodeView signature should be malformed."""
    sample = tmp_path / "unknown-codeview.exe"

    payload = b"ABCD" + b"\x00" * 28
    pointer = 0x30

    sample.write_bytes(b"MZ" + b"\x00" * (pointer - 2) + payload)

    debug_entry = _mock_debug_entry(
        debug_type=IMAGE_DEBUG_TYPE_CODEVIEW,
        pointer_to_raw_data=pointer,
        size_of_data=len(payload),
    )
    pe = _mock_pe((debug_entry,))

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed_entries"] == 1

    entry = result.data["entries"][0]

    assert entry["signature"] == "ABCD"
    assert entry["malformed"] is True


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.debug.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = DebugDirectoryAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = DebugDirectoryAnalyzer()

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
    analyzer = DebugDirectoryAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
