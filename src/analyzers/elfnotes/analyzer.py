"""ELF note, Build-ID, GNU property, and ABI metadata analysis."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFNoteAnalysisData,
    ELFNoteEntry,
    ELFNoteSection,
)

NT_GNU_ABI_TAG = "NT_GNU_ABI_TAG"
NT_GNU_BUILD_ID = "NT_GNU_BUILD_ID"
NT_GNU_PROPERTY_TYPE_0 = "NT_GNU_PROPERTY_TYPE_0"

GNU_PROPERTY_X86_FEATURE_1_AND = "GNU_PROPERTY_X86_FEATURE_1_AND"

GNU_PROPERTY_X86_FEATURE_1_IBT = 1 << 0
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 1 << 1


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _as_int(
    value: object,
) -> int | None:
    """Convert parser values to integers when possible."""
    if isinstance(
        value,
        bool,
    ):
        return int(value)

    if isinstance(
        value,
        int,
    ):
        return value

    return None


def _as_text(
    value: object,
) -> str | None:
    """Normalize parser values to text."""
    if value is None:
        return None

    if isinstance(
        value,
        bytes,
    ):
        try:
            return value.decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            return value.hex()

    return str(value)


def _build_id_from_desc(
    description: object,
) -> str | None:
    """Normalize GNU Build-ID note descriptions."""
    if isinstance(
        description,
        bytes,
    ):
        return description.hex()

    if isinstance(
        description,
        str,
    ):
        value = (
            description.strip()
            .replace(
                " ",
                "",
            )
            .lower()
        )

        return value if value else None

    return None


def _normalize_abi_os(
    value: object,
) -> str | None:
    """Normalize GNU ABI operating-system identifiers."""
    text = _as_text(value)

    if text is None:
        return None

    mapping = {
        "ELF_NOTE_OS_LINUX": "Linux",
        "ELF_NOTE_OS_GNU": "GNU",
        "ELF_NOTE_OS_SOLARIS2": "Solaris",
        "ELF_NOTE_OS_FREEBSD": "FreeBSD",
    }

    return mapping.get(
        text,
        text,
    )


def _abi_values(
    description: object,
) -> tuple[
    str | None,
    int | None,
    int | None,
    int | None,
]:
    """Normalize GNU ABI tag metadata."""
    if not isinstance(
        description,
        Mapping,
    ):
        return (
            None,
            None,
            None,
            None,
        )

    abi_os = _normalize_abi_os(description.get("abi_os"))

    major = _as_int(description.get("abi_major"))

    minor = _as_int(description.get("abi_minor"))

    patch = _as_int(description.get("abi_tiny"))

    if patch is None:
        patch = _as_int(description.get("abi_patch"))

    return (
        abi_os,
        major,
        minor,
        patch,
    )


def _gnu_property_bits(
    description: object,
) -> tuple[
    bool,
    bool,
    str | None,
    str | None,
]:
    """Extract common x86 GNU property hardening bits."""
    if isinstance(
        description,
        str | bytes,
    ) or not isinstance(
        description,
        Sequence,
    ):
        return (
            False,
            False,
            None,
            None,
        )

    ibt_enabled = False
    shstk_enabled = False

    property_type_name: str | None = None
    property_value: str | None = None

    for item in description:
        if not isinstance(
            item,
            Mapping,
        ):
            continue

        property_type = item.get("pr_type")

        property_data = item.get("pr_data")

        property_type_text = _as_text(property_type)

        property_data_int = _as_int(property_data)

        if property_type_text != GNU_PROPERTY_X86_FEATURE_1_AND:
            continue

        property_type_name = GNU_PROPERTY_X86_FEATURE_1_AND

        if property_data_int is None:
            continue

        ibt_enabled = bool(property_data_int & GNU_PROPERTY_X86_FEATURE_1_IBT)

        shstk_enabled = bool(property_data_int & GNU_PROPERTY_X86_FEATURE_1_SHSTK)

        property_value = f"0x{property_data_int:x}"

    return (
        ibt_enabled,
        shstk_enabled,
        property_type_name,
        property_value,
    )


def _description_text(
    description: object,
) -> str | None:
    """Produce a safe descriptive representation of note data."""
    if description is None:
        return None

    if isinstance(
        description,
        str,
    ):
        return description

    if isinstance(
        description,
        bytes,
    ):
        return description.hex()

    if isinstance(
        description,
        Mapping,
    ):
        return str(dict(description))

    if isinstance(
        description,
        Sequence,
    ):
        normalized: list[object] = []

        for item in description:
            if isinstance(
                item,
                Mapping,
            ):
                normalized.append(dict(item))
            else:
                normalized.append(item)

        return str(normalized)

    return str(description)


def _normalize_note(
    *,
    section_name: str,
    note: object,
) -> ELFNoteEntry:
    """Normalize one ELF note."""
    owner = _as_text(
        getattr(
            note,
            "n_name",
            None,
        )
    )

    if owner is None:
        owner = "UNKNOWN"

    note_type = _as_text(
        getattr(
            note,
            "n_type",
            None,
        )
    )

    if note_type is None:
        note_type = "UNKNOWN"

    description = getattr(
        note,
        "n_desc",
        None,
    )

    build_id: str | None = None

    abi_os: str | None = None
    abi_major: int | None = None
    abi_minor: int | None = None
    abi_patch: int | None = None

    gnu_property_type: str | None = None
    gnu_property_value: str | None = None

    if note_type == NT_GNU_BUILD_ID:
        build_id = _build_id_from_desc(description)

    elif note_type == NT_GNU_ABI_TAG:
        (
            abi_os,
            abi_major,
            abi_minor,
            abi_patch,
        ) = _abi_values(description)

    elif note_type == NT_GNU_PROPERTY_TYPE_0:
        (
            _,
            _,
            gnu_property_type,
            gnu_property_value,
        ) = _gnu_property_bits(description)

    return ELFNoteEntry(
        section_name=section_name,
        owner=owner,
        note_type=note_type,
        description=(_description_text(description)),
        build_id=build_id,
        abi_os=abi_os,
        abi_major=abi_major,
        abi_minor=abi_minor,
        abi_patch=abi_patch,
        gnu_property_type=(gnu_property_type),
        gnu_property_value=(gnu_property_value),
        malformed=False,
    )


def _extract_note_section(
    section: NoteSection,
) -> ELFNoteSection:
    """Normalize one ELF note section."""
    section_name = section.name or "(unnamed)"

    notes: list[ELFNoteEntry] = []

    malformed = 0

    try:
        entries = tuple(section.iter_notes())

    except Exception:
        return ELFNoteSection(
            name=section_name,
            note_count=0,
            malformed_note_count=1,
            notes=(),
        )

    for note in entries:
        try:
            notes.append(
                _normalize_note(
                    section_name=(section_name),
                    note=note,
                )
            )

        except Exception:
            malformed += 1

    return ELFNoteSection(
        name=section_name,
        note_count=len(notes),
        malformed_note_count=(malformed),
        notes=tuple(notes),
    )


def _extract_sections(
    elf: ELFFile,
) -> tuple[ELFNoteSection, ...]:
    """Extract all ELF note sections."""
    sections: list[ELFNoteSection] = []

    for section in elf.iter_sections():
        if not isinstance(
            section,
            NoteSection,
        ):
            continue

        sections.append(_extract_note_section(section))

    return tuple(sections)


def _extract_security_properties(
    elf: ELFFile,
) -> tuple[
    bool,
    bool,
]:
    """Extract aggregated GNU property hardening flags."""
    ibt_enabled = False
    shstk_enabled = False

    for section in elf.iter_sections():
        if not isinstance(
            section,
            NoteSection,
        ):
            continue

        try:
            notes = tuple(section.iter_notes())

        except Exception:
            continue

        for note in notes:
            note_type = _as_text(
                getattr(
                    note,
                    "n_type",
                    None,
                )
            )

            if note_type != NT_GNU_PROPERTY_TYPE_0:
                continue

            (
                note_ibt,
                note_shstk,
                _,
                _,
            ) = _gnu_property_bits(
                getattr(
                    note,
                    "n_desc",
                    None,
                )
            )

            ibt_enabled = ibt_enabled or note_ibt

            shstk_enabled = shstk_enabled or note_shstk

    return (
        ibt_enabled,
        shstk_enabled,
    )


def _build_data(
    elf: ELFFile,
) -> ELFNoteAnalysisData:
    """Build normalized ELF note-analysis data."""
    sections = _extract_sections(elf)

    notes = tuple(note for section in sections for note in section.notes)

    build_id: str | None = None

    abi_os: str | None = None
    abi_major: int | None = None
    abi_minor: int | None = None
    abi_patch: int | None = None

    gnu_property_present = False

    for note in notes:
        if build_id is None and note.build_id:
            build_id = note.build_id

        if abi_os is None and note.note_type == NT_GNU_ABI_TAG:
            abi_os = note.abi_os
            abi_major = note.abi_major
            abi_minor = note.abi_minor
            abi_patch = note.abi_patch

        if note.note_type == NT_GNU_PROPERTY_TYPE_0:
            gnu_property_present = True

    (
        ibt_enabled,
        shstk_enabled,
    ) = _extract_security_properties(elf)

    return ELFNoteAnalysisData(
        note_sections_present=bool(sections),
        note_section_count=len(sections),
        note_count=len(notes),
        malformed_note_count=sum(section.malformed_note_count for section in sections),
        build_id_present=(build_id is not None),
        build_id=build_id,
        abi_tag_present=any(note.note_type == NT_GNU_ABI_TAG for note in notes),
        abi_os=abi_os,
        abi_major=abi_major,
        abi_minor=abi_minor,
        abi_patch=abi_patch,
        gnu_property_present=(gnu_property_present),
        ibt_enabled=(ibt_enabled),
        shstk_enabled=(shstk_enabled),
        sections=sections,
    )


class ELFNotesAnalyzer:
    """Analyze ELF notes, Build-ID, ABI tags, and GNU properties."""

    name = "elfnotes"
    version = "0.1.0"

    supported_families = frozenset(
        {
            "elf",
        }
    )

    def supports(
        self,
        family: str,
    ) -> bool:
        """Return whether this analyzer supports the family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze ELF note structures."""
        started_at = datetime.now(UTC)

        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            with resolved_path.open("rb") as file_object:
                elf = _load_elf(file_object)

                analysis_data = _build_data(elf)

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.COMPLETED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                findings=(),
                data=(analysis_data.model_dump(mode="json")),
            )

        except ValueError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.FAILED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                errors=(
                    AnalyzerError(
                        error_type=(type(error).__name__),
                        message=str(error),
                        recoverable=False,
                    ),
                ),
            )

        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.PARTIAL),
                started_at=(started_at),
                duration_ms=(duration_ms),
                errors=(
                    AnalyzerError(
                        error_type=(type(error).__name__),
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
