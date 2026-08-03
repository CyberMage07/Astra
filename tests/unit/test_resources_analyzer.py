"""Tests for Astra PE resource analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.resources import ResourcesAnalyzer
from packages.schemas import AnalysisStatus


def _resource_tree(
    *,
    type_id: int,
    name_id: int,
    language_id: int,
    rva: int,
    size: int,
) -> MagicMock:
    """Create a mocked PE resource tree containing one resource."""
    structure = MagicMock()
    structure.OffsetToData = rva
    structure.Size = size

    data = MagicMock()
    data.struct = structure

    language_entry = MagicMock()
    language_entry.id = language_id
    language_entry.name = None
    language_entry.data = data

    name_directory = MagicMock()
    name_directory.entries = [language_entry]

    name_entry = MagicMock()
    name_entry.id = name_id
    name_entry.name = None
    name_entry.directory = name_directory

    type_directory = MagicMock()
    type_directory.entries = [name_entry]

    type_entry = MagicMock()
    type_entry.id = type_id
    type_entry.name = None
    type_entry.directory = type_directory

    root = MagicMock()
    root.entries = [type_entry]

    return root


def _mock_pe(
    *,
    payload: bytes,
    resource_tree: MagicMock | None,
    rva: int = 0x1000,
    offset: int = 0x400,
) -> MagicMock:
    """Create a mocked PE containing resource data."""
    image = bytearray(rva + len(payload))
    image[rva : rva + len(payload)] = payload

    pe = MagicMock()

    if resource_tree is not None:
        pe.DIRECTORY_ENTRY_RESOURCE = resource_tree

    pe.get_memory_mapped_image.return_value = bytes(image)
    pe.get_offset_from_rva.return_value = offset

    return pe


def test_resources_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ResourcesAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_manifest_resource_is_normalized(
    tmp_path: Path,
) -> None:
    """Ordinary manifest resources should be normalized without findings."""
    sample = tmp_path / "manifest.exe"
    sample.write_bytes(b"MZ")

    payload = b"<assembly></assembly>"
    tree = _resource_tree(
        type_id=24,
        name_id=1,
        language_id=9,
        rva=0x1000,
        size=len(payload),
    )
    pe = _mock_pe(
        payload=payload,
        resource_tree=tree,
    )

    with patch(
        "analyzers.resources.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["resource_count"] == 1
    assert result.data["manifest_count"] == 1
    assert result.data["embedded_executables"] == 0
    assert result.findings == ()

    resource = result.data["resources"][0]

    assert resource["resource_type"] == "manifest"
    assert resource["name"] == "1"
    assert resource["language"] == "English"
    assert resource["size"] == len(payload)


def test_embedded_pe_resource_generates_finding(
    tmp_path: Path,
) -> None:
    """Embedded PE payloads should produce a high-severity finding."""
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ")

    payload = b"MZ" + b"\x00" * 128
    tree = _resource_tree(
        type_id=10,
        name_id=101,
        language_id=9,
        rva=0x1000,
        size=len(payload),
    )
    pe = _mock_pe(
        payload=payload,
        resource_tree=tree,
    )

    with patch(
        "analyzers.resources.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["embedded_executables"] == 1
    assert result.data["rcdata_count"] == 1

    resource = result.data["resources"][0]

    assert resource["embedded_file_type"] == "pe"
    assert resource["is_executable"] is True

    assert any(
        finding.title == "Embedded executable resources detected" for finding in result.findings
    )


def test_embedded_zip_resource_generates_finding(
    tmp_path: Path,
) -> None:
    """Embedded ZIP archives should be detected."""
    sample = tmp_path / "archive.exe"
    sample.write_bytes(b"MZ")

    payload = b"PK\x03\x04" + b"\x00" * 64
    tree = _resource_tree(
        type_id=10,
        name_id=202,
        language_id=9,
        rva=0x1000,
        size=len(payload),
    )
    pe = _mock_pe(
        payload=payload,
        resource_tree=tree,
    )

    with patch(
        "analyzers.resources.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["embedded_archives"] == 1
    assert result.data["resources"][0]["embedded_file_type"] == "zip"

    assert any(
        finding.title == "Embedded archive resources detected" for finding in result.findings
    )


def test_high_entropy_icon_is_not_flagged(
    tmp_path: Path,
) -> None:
    """Compressed icon data should not generate an entropy finding."""
    sample = tmp_path / "icon.exe"
    sample.write_bytes(b"MZ")

    payload = bytes(range(256)) * 16
    tree = _resource_tree(
        type_id=3,
        name_id=1,
        language_id=9,
        rva=0x1000,
        size=len(payload),
    )
    pe = _mock_pe(
        payload=payload,
        resource_tree=tree,
    )

    with patch(
        "analyzers.resources.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["high_entropy_resources"] == 1
    assert result.data["icon_count"] == 1
    assert result.findings == ()


def test_pe_without_resources_returns_empty_result(
    tmp_path: Path,
) -> None:
    """PE files without resources should complete with empty data."""
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        payload=b"",
        resource_tree=None,
    )

    with patch(
        "analyzers.resources.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["resource_count"] == 0
    assert result.data["resources"] == []
    assert result.data["largest_resource_size"] == 0
    assert result.findings == ()


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE input should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    result = ResourcesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ResourcesAnalyzer()

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
    analyzer = ResourcesAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
