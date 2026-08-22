"""Schemas for ELF dynamic linking, PLT, GOT, and binding analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFDynamicSectionInfo(BaseModel):
    """One normalized ELF dynamic-linking related section."""

    model_config = ConfigDict(frozen=True)

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

    entry_size: int = Field(
        default=0,
        ge=0,
    )

    flags: int = Field(
        default=0,
        ge=0,
    )

    writable: bool = False
    executable: bool = False
    allocatable: bool = False

    entry_count: int = Field(
        default=0,
        ge=0,
    )


class ELFDynamicLinkingAnalysisData(BaseModel):
    """Structured ELF dynamic linking and PLT/GOT analysis output."""

    model_config = ConfigDict(frozen=True)

    dynamic_linking_present: bool = False

    plt_present: bool = False
    plt_got_present: bool = False
    plt_sec_present: bool = False

    got_present: bool = False
    got_plt_present: bool = False

    plt_section_count: int = Field(
        default=0,
        ge=0,
    )

    got_section_count: int = Field(
        default=0,
        ge=0,
    )

    plt_entry_count: int = Field(
        default=0,
        ge=0,
    )

    got_entry_estimate: int = Field(
        default=0,
        ge=0,
    )

    plt_relocation_count: int = Field(
        default=0,
        ge=0,
    )

    plt_got_address: int | None = Field(
        default=None,
        ge=0,
    )

    jmprel_address: int | None = Field(
        default=None,
        ge=0,
    )

    plt_relocation_size: int = Field(
        default=0,
        ge=0,
    )

    plt_relocation_type: str | None = None

    bind_now: bool = False
    lazy_binding: bool = False

    relro: bool = False
    full_relro: bool = False

    writable_got: bool = False

    malformed_entry_count: int = Field(
        default=0,
        ge=0,
    )

    suspicious_dynamic_linking: bool = False

    sections: tuple[
        ELFDynamicSectionInfo,
        ...,
    ] = ()
