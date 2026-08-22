"""Schemas for ELF section entropy and layout analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFSectionEntry(BaseModel):
    """One normalized ELF section with entropy and anomaly metadata."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(
        ge=0,
    )

    name: str
    section_type: str

    address: int = Field(
        default=0,
        ge=0,
    )

    offset: int = Field(
        default=0,
        ge=0,
    )

    size: int = Field(
        default=0,
        ge=0,
    )

    flags: int = Field(
        default=0,
        ge=0,
    )

    alignment: int = Field(
        default=0,
        ge=0,
    )

    entropy: float = Field(
        default=0.0,
        ge=0.0,
        le=8.0,
    )

    allocatable: bool = False
    executable: bool = False
    writable: bool = False
    rwx: bool = False

    high_entropy: bool = False
    suspicious_name: bool = False

    zero_sized_mapped: bool = False
    overlapping: bool = False
    out_of_bounds: bool = False
    malformed: bool = False


class ELFSectionAnalysisData(BaseModel):
    """Structured ELF section entropy and layout analysis output."""

    model_config = ConfigDict(frozen=True)

    section_count: int = Field(
        default=0,
        ge=0,
    )

    executable_section_count: int = Field(
        default=0,
        ge=0,
    )

    writable_section_count: int = Field(
        default=0,
        ge=0,
    )

    rwx_section_count: int = Field(
        default=0,
        ge=0,
    )

    high_entropy_section_count: int = Field(
        default=0,
        ge=0,
    )

    suspicious_name_count: int = Field(
        default=0,
        ge=0,
    )

    zero_sized_mapped_count: int = Field(
        default=0,
        ge=0,
    )

    overlapping_section_count: int = Field(
        default=0,
        ge=0,
    )

    out_of_bounds_section_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_section_count: int = Field(
        default=0,
        ge=0,
    )

    unusually_large_section_table: bool = False

    average_entropy: float = Field(
        default=0.0,
        ge=0.0,
        le=8.0,
    )

    maximum_entropy: float = Field(
        default=0.0,
        ge=0.0,
        le=8.0,
    )

    sections: tuple[
        ELFSectionEntry,
        ...,
    ] = ()
