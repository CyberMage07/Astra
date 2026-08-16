"""Schemas for ELF note and ABI metadata analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFNoteEntry(BaseModel):
    """One normalized ELF note entry."""

    model_config = ConfigDict(frozen=True)

    section_name: str
    owner: str
    note_type: str

    description: str | None = None

    build_id: str | None = None

    abi_os: str | None = None
    abi_major: int | None = Field(
        default=None,
        ge=0,
    )
    abi_minor: int | None = Field(
        default=None,
        ge=0,
    )
    abi_patch: int | None = Field(
        default=None,
        ge=0,
    )

    gnu_property_type: str | None = None
    gnu_property_value: str | None = None

    malformed: bool = False


class ELFNoteSection(BaseModel):
    """One ELF note section."""

    model_config = ConfigDict(frozen=True)

    name: str

    note_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_note_count: int = Field(
        default=0,
        ge=0,
    )

    notes: tuple[ELFNoteEntry, ...] = ()


class ELFNoteAnalysisData(BaseModel):
    """Structured ELF note and ABI metadata output."""

    model_config = ConfigDict(frozen=True)

    note_sections_present: bool

    note_section_count: int = Field(
        default=0,
        ge=0,
    )

    note_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_note_count: int = Field(
        default=0,
        ge=0,
    )

    build_id_present: bool = False
    build_id: str | None = None

    abi_tag_present: bool = False
    abi_os: str | None = None

    abi_major: int | None = Field(
        default=None,
        ge=0,
    )
    abi_minor: int | None = Field(
        default=None,
        ge=0,
    )
    abi_patch: int | None = Field(
        default=None,
        ge=0,
    )

    gnu_property_present: bool = False

    ibt_enabled: bool = False
    shstk_enabled: bool = False

    sections: tuple[ELFNoteSection, ...] = ()
