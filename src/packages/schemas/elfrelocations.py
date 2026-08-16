"""Schemas for ELF relocation analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFRelocationEntry(BaseModel):
    """One normalized ELF relocation entry."""

    model_config = ConfigDict(frozen=True)

    section_name: str

    offset: int = Field(
        default=0,
        ge=0,
    )

    relocation_type: int = Field(
        default=0,
        ge=0,
    )

    relocation_type_name: str

    symbol_index: int = Field(
        default=0,
        ge=0,
    )

    symbol_name: str | None = None

    addend: int | None = None

    has_symbol: bool = False
    imported_symbol: bool = False

    plt_related: bool = False
    got_related: bool = False

    malformed: bool = False


class ELFRelocationSection(BaseModel):
    """One ELF relocation section."""

    model_config = ConfigDict(frozen=True)

    name: str
    section_type: str

    entry_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_entry_count: int = Field(
        default=0,
        ge=0,
    )

    relocations: tuple[ELFRelocationEntry, ...] = ()


class ELFRelocationAnalysisData(BaseModel):
    """Structured ELF relocation-analysis output."""

    model_config = ConfigDict(frozen=True)

    relocation_sections_present: bool

    relocation_section_count: int = Field(
        default=0,
        ge=0,
    )

    relocation_count: int = Field(
        default=0,
        ge=0,
    )

    rela_count: int = Field(
        default=0,
        ge=0,
    )

    rel_count: int = Field(
        default=0,
        ge=0,
    )

    symbol_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    imported_symbol_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    plt_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    got_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    relocation_types: tuple[str, ...] = ()

    sections: tuple[ELFRelocationSection, ...] = ()
