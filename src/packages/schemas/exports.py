"""Schemas for PE export-table analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ExportEntry(BaseModel):
    """One normalized PE export entry."""

    model_config = ConfigDict(frozen=True)

    ordinal: int = Field(ge=0)
    name: str | None = None

    address: int = Field(ge=0)
    rva: int = Field(ge=0)

    forwarder: str | None = None
    is_forwarded: bool = False

    section_name: str | None = None
    is_mapped: bool = False
    is_executable: bool = False

    suspicious_name: bool = False
    malformed: bool = False


class ExportAnalysisData(BaseModel):
    """Structured PE export-table analysis output."""

    model_config = ConfigDict(frozen=True)

    export_directory_present: bool

    module_name: str | None = None

    export_count: int = Field(default=0, ge=0)
    named_export_count: int = Field(default=0, ge=0)
    ordinal_only_count: int = Field(default=0, ge=0)
    forwarded_export_count: int = Field(default=0, ge=0)

    executable_export_count: int = Field(default=0, ge=0)
    unmapped_export_count: int = Field(default=0, ge=0)

    suspicious_name_count: int = Field(default=0, ge=0)
    malformed_export_count: int = Field(default=0, ge=0)

    duplicate_name_count: int = Field(default=0, ge=0)
    duplicate_ordinal_count: int = Field(default=0, ge=0)

    unusually_large_export_table: bool = False

    exports: tuple[ExportEntry, ...] = ()
