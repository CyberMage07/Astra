"""Schemas for PE Rich Header analysis."""

from pydantic import BaseModel, ConfigDict, Field


class RichHeaderEntry(BaseModel):
    """One decoded Rich Header compiler or toolchain record."""

    model_config = ConfigDict(frozen=True)

    product_id: int = Field(ge=0, le=0xFFFF)
    build_number: int = Field(ge=0, le=0xFFFF)
    count: int = Field(ge=0)

    component_id: int = Field(ge=0, le=0xFFFFFFFF)
    product_name: str | None = None
    toolchain_family: str | None = None


class RichHeaderAnalysisData(BaseModel):
    """Structured PE Rich Header analysis output."""

    model_config = ConfigDict(frozen=True)

    rich_header_present: bool

    dans_offset: int | None = Field(
        default=None,
        ge=0,
    )
    rich_offset: int | None = Field(
        default=None,
        ge=0,
    )
    xor_key: int | None = Field(
        default=None,
        ge=0,
        le=0xFFFFFFFF,
    )

    checksum_valid: bool | None = None
    malformed: bool = False

    entry_count: int = Field(
        default=0,
        ge=0,
    )
    total_object_count: int = Field(
        default=0,
        ge=0,
    )

    unique_product_ids: tuple[int, ...] = ()
    unique_build_numbers: tuple[int, ...] = ()
    toolchain_families: tuple[str, ...] = ()

    entries: tuple[RichHeaderEntry, ...] = ()

    duplicate_entries: int = Field(
        default=0,
        ge=0,
    )
    zero_count_entries: int = Field(
        default=0,
        ge=0,
    )
    unknown_product_entries: int = Field(
        default=0,
        ge=0,
    )
