"""Tests for Astra ELF note and ABI metadata analysis."""

from collections.abc import Sequence
from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfnotes import ELFNotesAnalyzer
from packages.schemas import (
    AnalysisStatus,
    ELFNoteEntry,
)


def _mock_note(
    *,
    owner: str = "GNU",
    note_type: str,
    description: object,
) -> MagicMock:
    """Create one ELF note fixture."""
    note = MagicMock()

    note.n_name = owner
    note.n_type = note_type
    note.n_desc = description

    return note


def _mock_note_section(
    *,
    name: str,
    notes: Sequence[MagicMock] | None = None,
) -> MagicMock:
    """Create one ELF note-section fixture."""
    section = MagicMock()

    section.name = name
    section.iter_notes.return_value = list(notes) if notes is not None else []

    return section


def _mock_elf(
    *,
    sections: Sequence[object] | None = None,
) -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.iter_sections.return_value = list(sections) if sections is not None else []

    return elf


def test_elfnotes_analyzer_contract() -> None:
    """Analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ELFNotesAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_no_notes_returns_empty_result(
    tmp_path: Path,
) -> None:
    """ELF files without note sections should return empty metadata."""
    sample = tmp_path / "empty.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elfnotes.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["note_sections_present"] is False
    assert result.data["note_section_count"] == 0
    assert result.data["note_count"] == 0

    assert result.data["build_id_present"] is False
    assert result.data["build_id"] is None

    assert result.data["abi_tag_present"] is False
    assert result.data["gnu_property_present"] is False

    assert result.data["ibt_enabled"] is False
    assert result.data["shstk_enabled"] is False


def test_build_id_is_normalized(
    tmp_path: Path,
) -> None:
    """GNU Build-ID notes should be normalized."""
    sample = tmp_path / "buildid.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description=("4E297D3B427342E1DA6B66F5CA0FD279F43F3AFE"),
    )

    section = _mock_note_section(
        name=".note.gnu.build-id",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["build_id_present"] is True

    assert result.data["build_id"] == "4e297d3b427342e1da6b66f5ca0fd279f43f3afe"

    normalized = result.data["sections"][0]["notes"][0]

    assert normalized["owner"] == "GNU"
    assert normalized["note_type"] == "NT_GNU_BUILD_ID"
    assert normalized["build_id"] == result.data["build_id"]


def test_binary_build_id_is_normalized(
    tmp_path: Path,
) -> None:
    """Binary Build-ID descriptors should become hexadecimal strings."""
    sample = tmp_path / "binary-buildid.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description=b"\xaa\xbb\xcc\xdd",
    )

    section = _mock_note_section(
        name=".note.gnu.build-id",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["build_id"] == "aabbccdd"


def test_abi_tag_is_normalized(
    tmp_path: Path,
) -> None:
    """GNU ABI tags should expose OS and version metadata."""
    sample = tmp_path / "abi.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_ABI_TAG",
        description={
            "abi_os": "ELF_NOTE_OS_LINUX",
            "abi_major": 4,
            "abi_minor": 4,
            "abi_tiny": 0,
        },
    )

    section = _mock_note_section(
        name=".note.ABI-tag",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["abi_tag_present"] is True
    assert result.data["abi_os"] == "Linux"
    assert result.data["abi_major"] == 4
    assert result.data["abi_minor"] == 4
    assert result.data["abi_patch"] == 0


def test_abi_patch_fallback_is_supported(
    tmp_path: Path,
) -> None:
    """Alternative abi_patch field names should remain supported."""
    sample = tmp_path / "abi-patch.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_ABI_TAG",
        description={
            "abi_os": "ELF_NOTE_OS_FREEBSD",
            "abi_major": 13,
            "abi_minor": 2,
            "abi_patch": 1,
        },
    )

    section = _mock_note_section(
        name=".note.ABI-tag",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["abi_os"] == "FreeBSD"
    assert result.data["abi_major"] == 13
    assert result.data["abi_minor"] == 2
    assert result.data["abi_patch"] == 1


def test_gnu_property_detects_ibt(
    tmp_path: Path,
) -> None:
    """GNU x86 feature properties should detect IBT."""
    sample = tmp_path / "ibt.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_PROPERTY_TYPE_0",
        description=[
            {
                "pr_type": ("GNU_PROPERTY_X86_FEATURE_1_AND"),
                "pr_datasz": 4,
                "pr_data": 1,
            }
        ],
    )

    section = _mock_note_section(
        name=".note.gnu.property",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["gnu_property_present"] is True
    assert result.data["ibt_enabled"] is True
    assert result.data["shstk_enabled"] is False


def test_gnu_property_detects_shstk(
    tmp_path: Path,
) -> None:
    """GNU x86 feature properties should detect SHSTK."""
    sample = tmp_path / "shstk.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_PROPERTY_TYPE_0",
        description=[
            {
                "pr_type": ("GNU_PROPERTY_X86_FEATURE_1_AND"),
                "pr_datasz": 4,
                "pr_data": 2,
            }
        ],
    )

    section = _mock_note_section(
        name=".note.gnu.property",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["ibt_enabled"] is False
    assert result.data["shstk_enabled"] is True


def test_combined_gnu_property_detects_ibt_and_shstk(
    tmp_path: Path,
) -> None:
    """Feature value 0x3 should enable IBT and SHSTK."""
    sample = tmp_path / "cet.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_PROPERTY_TYPE_0",
        description=[
            {
                "pr_type": ("GNU_PROPERTY_X86_FEATURE_1_AND"),
                "pr_datasz": 4,
                "pr_data": 3,
            },
            {
                "pr_type": ("GNU_PROPERTY_X86_ISA_1_NEEDED"),
                "pr_datasz": 4,
                "pr_data": 1,
            },
        ],
    )

    section = _mock_note_section(
        name=".note.gnu.property",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["ibt_enabled"] is True
    assert result.data["shstk_enabled"] is True

    normalized = result.data["sections"][0]["notes"][0]

    assert normalized["gnu_property_type"] == "GNU_PROPERTY_X86_FEATURE_1_AND"
    assert normalized["gnu_property_value"] == "0x3"


def test_unrelated_gnu_property_is_preserved_without_features(
    tmp_path: Path,
) -> None:
    """Unrelated GNU properties should not enable CET flags."""
    sample = tmp_path / "property.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_PROPERTY_TYPE_0",
        description=[
            {
                "pr_type": ("GNU_PROPERTY_X86_ISA_1_NEEDED"),
                "pr_datasz": 4,
                "pr_data": 1,
            }
        ],
    )

    section = _mock_note_section(
        name=".note.gnu.property",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["gnu_property_present"] is True
    assert result.data["ibt_enabled"] is False
    assert result.data["shstk_enabled"] is False


def test_multiple_note_sections_are_counted(
    tmp_path: Path,
) -> None:
    """Multiple note sections should be aggregated."""
    sample = tmp_path / "multiple.elf"
    sample.write_bytes(b"\x7fELF")

    build_id = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description="abcdef",
    )

    abi = _mock_note(
        note_type="NT_GNU_ABI_TAG",
        description={
            "abi_os": "ELF_NOTE_OS_LINUX",
            "abi_major": 6,
            "abi_minor": 1,
            "abi_tiny": 0,
        },
    )

    sections: Sequence[object] = (
        _mock_note_section(
            name=".note.gnu.build-id",
            notes=[build_id],
        ),
        _mock_note_section(
            name=".note.ABI-tag",
            notes=[abi],
        ),
    )

    elf = _mock_elf(
        sections=sections,
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["note_section_count"] == 2
    assert result.data["note_count"] == 2
    assert result.data["build_id_present"] is True
    assert result.data["abi_tag_present"] is True


def test_malformed_note_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed individual notes should not abort the section."""
    sample = tmp_path / "malformed.elf"
    sample.write_bytes(b"\x7fELF")

    good = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description="abcdef",
    )

    bad = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description="broken",
    )

    section = _mock_note_section(
        name=".note.gnu.build-id",
        notes=[
            good,
            bad,
        ],
    )

    elf = _mock_elf(
        sections=[section],
    )

    good_normalized = ELFNoteEntry(
        section_name=".note.gnu.build-id",
        owner="GNU",
        note_type="NT_GNU_BUILD_ID",
        description="abcdef",
        build_id="abcdef",
        malformed=False,
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfnotes.analyzer._normalize_note",
            side_effect=[
                good_normalized,
                RuntimeError("broken note"),
            ],
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["note_count"] == 1

    assert result.data["malformed_note_count"] == 1

    assert result.data["build_id"] == "abcdef"


def test_broken_note_section_is_counted(
    tmp_path: Path,
) -> None:
    """Broken note-section iteration should remain recoverable."""
    sample = tmp_path / "broken-section.elf"
    sample.write_bytes(b"\x7fELF")

    section = _mock_note_section(
        name=".note.bad",
    )

    section.iter_notes.side_effect = RuntimeError("broken note section")

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["malformed_note_count"] == 1


def test_analyzer_produces_no_findings(
    tmp_path: Path,
) -> None:
    """Normal ELF metadata notes should not generate findings."""
    sample = tmp_path / "normal.elf"
    sample.write_bytes(b"\x7fELF")

    note = _mock_note(
        note_type="NT_GNU_BUILD_ID",
        description="abcdef",
    )

    section = _mock_note_section(
        name=".note.gnu.build-id",
        notes=[note],
    )

    elf = _mock_elf(
        sections=[section],
    )

    with (
        patch(
            "analyzers.elfnotes.analyzer.NoteSection",
            MagicMock,
        ),
        patch(
            "analyzers.elfnotes.analyzer._load_elf",
            return_value=elf,
        ),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.findings == ()


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid ELF parsing should return a failed result."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.elfnotes.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

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
        "analyzers.elfnotes.analyzer._load_elf",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ELFNotesAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ELFNotesAnalyzer()

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
    analyzer = ELFNotesAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
