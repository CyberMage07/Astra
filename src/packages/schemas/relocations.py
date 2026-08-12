"""Schemas for PE base-relocation analysis."""

from pydantic import BaseModel, ConfigDict, Field


class RelocationEntry(BaseModel):
    """One normalized PE base-relocation entry."""

    model_config = ConfigDict(frozen=True)

    block_index: int = Field(ge=0)
    entry_index: int = Field(ge=0)

    relocation_type: int = Field(ge=0)
    relocation_type_name: str

    rva: int = Field(ge=0)
    virtual_address: int = Field(ge=0)

    section_name: str | None = None

    is_mapped: bool = False
    is_executable: bool = False
    is_writable: bool = False

    malformed: bool = False


class RelocationBlock(BaseModel):
    """One normalized PE relocation block."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)

    page_rva: int = Field(ge=0)
    block_size: int = Field(ge=0)

    entry_count: int = Field(default=0, ge=0)
    malformed_entry_count: int = Field(default=0, ge=0)

    entries: tuple[RelocationEntry, ...] = ()


class RelocationAnalysisData(BaseModel):
    """Structured PE base-relocation analysis output."""

    model_config = ConfigDict(frozen=True)

    relocation_directory_present: bool

    block_count: int = Field(default=0, ge=0)
    relocation_count: int = Field(default=0, ge=0)

    mapped_relocation_count: int = Field(default=0, ge=0)
    executable_relocation_count: int = Field(default=0, ge=0)
    writable_relocation_count: int = Field(default=0, ge=0)

    malformed_relocation_count: int = Field(default=0, ge=0)
    unknown_type_count: int = Field(default=0, ge=0)

    relocation_types: tuple[str, ...] = ()

    unusually_large_relocation_table: bool = False

    blocks: tuple[RelocationBlock, ...] = ()
