"""Schemas for PE TLS callback analysis."""

from pydantic import BaseModel, ConfigDict, Field


class TLSCallbackEntry(BaseModel):
    """Normalized PE TLS callback entry."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)
    virtual_address: int = Field(ge=0)
    relative_virtual_address: int | None = Field(
        default=None,
        ge=0,
    )
    file_offset: int | None = Field(
        default=None,
        ge=0,
    )
    section_name: str | None = None

    is_mapped: bool = False
    is_executable: bool = False
    is_writable: bool = False
    is_outside_image: bool = False


class TLSAnalysisData(BaseModel):
    """Structured PE TLS-directory analysis output."""

    model_config = ConfigDict(frozen=True)

    tls_present: bool
    callback_count: int = Field(default=0, ge=0)
    callbacks: tuple[TLSCallbackEntry, ...] = ()

    raw_data_start: int | None = Field(
        default=None,
        ge=0,
    )
    raw_data_end: int | None = Field(
        default=None,
        ge=0,
    )
    address_of_index: int | None = Field(
        default=None,
        ge=0,
    )
    address_of_callbacks: int | None = Field(
        default=None,
        ge=0,
    )

    size_of_zero_fill: int = Field(default=0, ge=0)
    characteristics: int = Field(default=0, ge=0)

    mapped_callbacks: int = Field(default=0, ge=0)
    executable_callbacks: int = Field(default=0, ge=0)
    writable_callbacks: int = Field(default=0, ge=0)
    outside_image_callbacks: int = Field(default=0, ge=0)
    suspicious_callbacks: int = Field(default=0, ge=0)
