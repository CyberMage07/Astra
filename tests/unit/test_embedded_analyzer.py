"""Tests for Astra embedded-payload discovery."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.embedded import EmbeddedAnalyzer
from packages.schemas import (
    AnalysisStatus,
    EmbeddedAnalysisLimits,
    EmbeddedPayloadLocation,
)


def _mock_resource_payload(
    *,
    offset: int = 0x100,
    size: int = 128,
    resource_type: int = 10,
    resource_name: int = 1,
) -> MagicMock:
    """Create a minimal PE resource tree."""
    language = MagicMock()
    language.data.struct.OffsetToData = offset
    language.data.struct.Size = size

    name_entry = MagicMock()
    name_entry.name = None
    name_entry.struct.Id = resource_name
    name_entry.directory.entries = [language]

    type_entry = MagicMock()
    type_entry.name = None
    type_entry.struct.Id = resource_type
    type_entry.directory.entries = [name_entry]

    root = MagicMock()
    root.entries = [type_entry]

    return root


def _mock_pe(
    *,
    resource_root: object | None = None,
    overlay_offset: int | None = None,
    resource_file_offset: int = 0x100,
) -> MagicMock:
    """Create a mocked PE parser object."""
    pe = MagicMock()

    if resource_root is None:
        del pe.DIRECTORY_ENTRY_RESOURCE
    else:
        pe.DIRECTORY_ENTRY_RESOURCE = resource_root

    pe.get_offset_from_rva.return_value = resource_file_offset
    pe.get_overlay_data_start_offset.return_value = overlay_offset

    return pe


def _mock_candidate(
    data: bytes,
    *,
    source: str = "resource",
    offset: int = 100,
    extraction_method: str = "pe-resource",
) -> MagicMock:
    """Create one normalized embedded-payload candidate."""
    candidate = MagicMock()
    candidate.data = data
    candidate.location = EmbeddedPayloadLocation(
        source=source,
        offset=offset,
        size=len(data),
    )
    candidate.extraction_method = extraction_method

    return candidate


def test_embedded_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = EmbeddedAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_embedded_payloads_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without interesting resources or overlay should be empty."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 1024)

    pe = _mock_pe()

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["embedded_payloads_present"] is False
    assert result.data["payload_count"] == 0
    assert result.data["total_extracted_bytes"] == 0
    assert result.findings == ()


def test_recursive_payload_preserves_parent_and_depth(
    tmp_path: Path,
) -> None:
    """Nested payloads should retain depth and parent relationships."""
    sample = tmp_path / "parent.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 1024)

    first_payload = b"MZ" + b"\x00" * 126
    second_payload = b"\x7fELF" + b"\x00" * 124

    analyzer = EmbeddedAnalyzer()

    first_candidate = _mock_candidate(
        first_payload,
        offset=100,
    )

    second_candidate = _mock_candidate(
        second_payload,
        offset=200,
    )

    call_count = 0

    def discover(
        sample_path: Path,
        family: str,
    ) -> list[object]:
        nonlocal call_count

        del sample_path, family

        call_count += 1

        if call_count == 1:
            return [first_candidate]

        if call_count == 2:
            return [second_candidate]

        return []

    with patch.object(
        analyzer,
        "_discover_candidates",
        side_effect=discover,
    ):
        result = analyzer.analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 2
    assert result.data["maximum_depth_reached"] == 2

    first = result.data["payloads"][0]
    second = result.data["payloads"][1]

    assert first["index"] == 0
    assert first["parent_index"] is None
    assert first["depth"] == 1

    assert second["index"] == 1
    assert second["parent_index"] == 0
    assert second["depth"] == 2

    assert second["identity"]["detected_family"] == "elf"


def test_root_sample_is_part_of_global_deduplication(
    tmp_path: Path,
) -> None:
    """An embedded copy of the root sample should be marked duplicate."""
    sample = tmp_path / "self.exe"

    root_data = b"MZ" + b"\x00" * 1022
    sample.write_bytes(root_data)

    analyzer = EmbeddedAnalyzer()

    candidate = _mock_candidate(
        root_data,
        offset=100,
    )

    with patch.object(
        analyzer,
        "_discover_candidates",
        return_value=[candidate],
    ):
        result = analyzer.analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 1
    assert result.data["duplicate_payload_count"] == 1
    assert result.data["payloads"][0]["duplicate"] is True
    assert result.data["payloads"][0]["analysis"]["analyzed"] is False


def test_recursion_depth_limit_is_enforced(
    tmp_path: Path,
) -> None:
    """Nested PE recursion must stop at the configured maximum depth."""
    sample = tmp_path / "depth.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 1024)

    analyzer = EmbeddedAnalyzer(
        limits=EmbeddedAnalysisLimits(
            maximum_depth=2,
        )
    )

    payload_one = b"MZ" + b"\x01" * 126
    payload_two = b"MZ" + b"\x02" * 126

    first_candidate = _mock_candidate(
        payload_one,
        offset=100,
    )

    second_candidate = _mock_candidate(
        payload_two,
        offset=200,
    )

    call_count = 0

    def discover(
        sample_path: Path,
        family: str,
    ) -> list[object]:
        nonlocal call_count

        del sample_path, family

        call_count += 1

        if call_count == 1:
            return [first_candidate]

        if call_count == 2:
            return [second_candidate]

        return []

    with patch.object(
        analyzer,
        "_discover_candidates",
        side_effect=discover,
    ):
        result = analyzer.analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 2
    assert result.data["maximum_depth_reached"] == 2
    assert result.data["recursion_limit_reached"] is True


def test_child_analyzer_summary_is_preserved(
    tmp_path: Path,
) -> None:
    """Recursive children should retain their independent Astra assessment."""
    sample = tmp_path / "parent.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 1024)

    payload = b"\x7fELF" + b"\x00" * 124

    candidate = _mock_candidate(
        payload,
        offset=100,
    )

    report = MagicMock()
    report.analyzer_results = (
        MagicMock(),
        MagicMock(),
    )
    report.completed_analyzers = 2
    report.failed_analyzers = 0
    report.findings = (MagicMock(),)
    report.assessment.classification.value = "suspicious"
    report.assessment.score = 55
    report.assessment.confidence = 80

    analyzer = EmbeddedAnalyzer(child_analyzer=lambda path: report)

    with patch.object(
        analyzer,
        "_discover_candidates",
        return_value=[candidate],
    ):
        result = analyzer.analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["analyzed_payload_count"] == 1

    analysis = result.data["payloads"][0]["analysis"]

    assert analysis["analyzed"] is True
    assert analysis["analyzer_count"] == 2
    assert analysis["completed_analyzers"] == 2
    assert analysis["failed_analyzers"] == 0
    assert analysis["finding_count"] == 1
    assert analysis["classification"] == "suspicious"
    assert analysis["risk_score"] == 55
    assert analysis["confidence"] == 80


def test_embedded_pe_resource_is_detected(
    tmp_path: Path,
) -> None:
    """An MZ resource should be identified as an embedded PE."""
    sample = tmp_path / "embedded.exe"

    payload = b"MZ" + b"\x00" * 126

    raw = b"MZ" + b"\x00" * (0x100 - 2) + payload + b"\x00" * 256

    sample.write_bytes(raw)

    root = _mock_resource_payload(
        offset=0x2000,
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["embedded_payloads_present"] is True
    assert result.data["payload_count"] == 1
    assert result.data["executable_payload_count"] == 1

    child = result.data["payloads"][0]

    assert child["identity"]["detected_family"] == "pe"
    assert child["identity"]["is_executable"] is True
    assert child["location"]["source"] == "resource"
    assert child["extraction_method"] == "pe-resource"

    assert any(
        finding.title == "Embedded executable payloads detected" for finding in result.findings
    )


def test_embedded_elf_resource_is_detected(
    tmp_path: Path,
) -> None:
    """An ELF resource should be identified independently of parent type."""
    sample = tmp_path / "parent.exe"

    payload = b"\x7fELF" + b"\x00" * 124

    raw = b"MZ" + b"\x00" * (0x100 - 2) + payload

    sample.write_bytes(raw)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 1
    assert result.data["executable_payload_count"] == 1
    assert result.data["payloads"][0]["identity"]["detected_family"] == "elf"


def test_embedded_zip_resource_is_detected(
    tmp_path: Path,
) -> None:
    """ZIP resources should be categorized as archives."""
    sample = tmp_path / "archive.exe"

    payload = b"PK\x03\x04" + b"\x00" * 124

    raw = b"MZ" + b"\x00" * (0x100 - 2) + payload

    sample.write_bytes(raw)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["archive_payload_count"] == 1
    assert result.data["payloads"][0]["identity"]["detected_family"] == "archive"


def test_embedded_pdf_resource_is_detected(
    tmp_path: Path,
) -> None:
    """PDF resources should be categorized as documents."""
    sample = tmp_path / "document.exe"

    payload = b"%PDF-1.7\n" + b"\x00" * 120

    raw = b"MZ" + b"\x00" * (0x100 - 2) + payload

    sample.write_bytes(raw)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["document_payload_count"] == 1
    assert result.data["payloads"][0]["identity"]["detected_family"] == "pdf"


def test_pe_overlay_payload_is_detected(
    tmp_path: Path,
) -> None:
    """Recognizable overlay content should become a payload candidate."""
    sample = tmp_path / "overlay.exe"

    overlay_offset = 256

    raw = b"MZ" + b"\x00" * (overlay_offset - 2) + b"\x7fELF" + b"\x00" * 124

    sample.write_bytes(raw)

    pe = _mock_pe(
        overlay_offset=overlay_offset,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 1

    child = result.data["payloads"][0]

    assert child["location"]["source"] == "overlay"
    assert child["extraction_method"] == "pe-overlay"
    assert child["identity"]["detected_family"] == "elf"


def test_unknown_resource_is_ignored(
    tmp_path: Path,
) -> None:
    """Unrecognized resource bytes should not become payload noise."""
    sample = tmp_path / "unknown.exe"

    payload = b"A" * 128

    raw = b"MZ" + b"\x00" * (0x100 - 2) + payload

    sample.write_bytes(raw)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 0


def test_duplicate_payloads_are_marked(
    tmp_path: Path,
) -> None:
    """Identical embedded payloads should be deduplicated by SHA-256."""
    sample = tmp_path / "duplicate.exe"

    payload = b"MZ" + b"\x00" * 126

    sample.write_bytes(b"MZ" + b"\x00" * 254 + payload + payload)

    first = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=first,
        overlay_offset=0x180,
        resource_file_offset=0x100,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 2
    assert result.data["duplicate_payload_count"] == 1

    assert result.data["payloads"][0]["duplicate"] is False
    assert result.data["payloads"][1]["duplicate"] is True


def test_payload_size_limit_truncates_payload(
    tmp_path: Path,
) -> None:
    """Oversized child payloads should be bounded safely."""
    sample = tmp_path / "large.exe"

    payload = b"MZ" + b"\x00" * 1022

    sample.write_bytes(b"MZ" + b"\x00" * 254 + payload)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    limits = EmbeddedAnalysisLimits(
        maximum_payload_size=128,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer(limits=limits).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 1
    assert result.data["payloads"][0]["truncated"] is True


def test_payload_count_limit_is_enforced(
    tmp_path: Path,
) -> None:
    """The payload count limit must stop excessive extraction."""
    sample = tmp_path / "many.exe"

    payload = b"MZ" + b"\x00" * 126

    sample.write_bytes(b"MZ" + b"\x00" * 254 + payload)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        overlay_offset=0x100,
        resource_file_offset=0x100,
    )

    limits = EmbeddedAnalysisLimits(
        maximum_payloads=1,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer(limits=limits).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["payload_count"] == 1
    assert result.data["payload_limit_reached"] is True


def test_total_byte_limit_is_enforced(
    tmp_path: Path,
) -> None:
    """Total extracted bytes should be globally bounded."""
    sample = tmp_path / "byte-limit.exe"

    payload = b"MZ" + b"\x00" * 254

    sample.write_bytes(b"MZ" + b"\x00" * 254 + payload)

    root = _mock_resource_payload(
        size=len(payload),
    )

    pe = _mock_pe(
        resource_root=root,
        resource_file_offset=0x100,
    )

    limits = EmbeddedAnalysisLimits(
        maximum_total_extracted_bytes=64,
    )

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = EmbeddedAnalyzer(limits=limits).analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["byte_limit_reached"] is True
    assert result.data["payloads"][0]["truncated"] is True

    assert any(
        finding.title == "Embedded payload analysis limits reached" for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Malformed PE input should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE"),
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected extraction failures should remain recoverable."""
    sample = tmp_path / "error.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.embedded.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected failure"),
    ):
        result = EmbeddedAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = EmbeddedAnalyzer()

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
    analyzer = EmbeddedAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
