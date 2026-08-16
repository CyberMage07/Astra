"""Schemas for ELF executable and shared-object analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFHeaderInfo(BaseModel):
    """Normalized ELF header information."""

    model_config = ConfigDict(frozen=True)

    architecture_bits: int = Field(
        ge=32,
        le=64,
    )

    endianness: str
    elf_type: str
    machine: str

    os_abi: str
    abi_version: int = Field(
        default=0,
        ge=0,
    )

    elf_version: int = Field(
        default=1,
        ge=0,
    )

    entry_point: int = Field(
        ge=0,
    )

    program_header_offset: int = Field(
        default=0,
        ge=0,
    )

    section_header_offset: int = Field(
        default=0,
        ge=0,
    )

    program_header_count: int = Field(
        default=0,
        ge=0,
    )

    section_header_count: int = Field(
        default=0,
        ge=0,
    )

    flags: int = Field(
        default=0,
        ge=0,
    )


class ELFSection(BaseModel):
    """Normalized ELF section information."""

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

    entry_size: int = Field(
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

    executable: bool = False
    writable: bool = False
    allocatable: bool = False


class ELFSegment(BaseModel):
    """Normalized ELF program-header segment."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(
        ge=0,
    )

    segment_type: str

    offset: int = Field(
        default=0,
        ge=0,
    )

    virtual_address: int = Field(
        default=0,
        ge=0,
    )

    physical_address: int = Field(
        default=0,
        ge=0,
    )

    file_size: int = Field(
        default=0,
        ge=0,
    )

    memory_size: int = Field(
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

    readable: bool = False
    writable: bool = False
    executable: bool = False


class ELFDynamicInfo(BaseModel):
    """Normalized ELF dynamic-linking metadata."""

    model_config = ConfigDict(frozen=True)

    dynamically_linked: bool = False

    interpreter: str | None = None

    needed_libraries: tuple[str, ...] = ()

    soname: str | None = None

    rpath: str | None = None
    runpath: str | None = None

    bind_now: bool = False

    dynamic_entry_count: int = Field(
        default=0,
        ge=0,
    )


class ELFSecurityInfo(BaseModel):
    """Normalized ELF hardening and security properties."""

    model_config = ConfigDict(frozen=True)

    pie: bool = False

    nx_enabled: bool = False
    executable_stack: bool = False

    relro: bool = False
    full_relro: bool = False

    bind_now: bool = False

    stripped: bool = False

    has_stack_canary: bool = False

    has_rpath: bool = False
    has_runpath: bool = False


class ELFAnalysisData(BaseModel):
    """Structured ELF static-analysis output."""

    model_config = ConfigDict(frozen=True)

    elf_present: bool

    header: ELFHeaderInfo

    sections: tuple[ELFSection, ...] = ()
    segments: tuple[ELFSegment, ...] = ()

    section_count: int = Field(
        default=0,
        ge=0,
    )

    segment_count: int = Field(
        default=0,
        ge=0,
    )

    dynamic: ELFDynamicInfo = ELFDynamicInfo()

    security: ELFSecurityInfo = ELFSecurityInfo()

    malformed: bool = False

    malformed_section_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_segment_count: int = Field(
        default=0,
        ge=0,
    )
