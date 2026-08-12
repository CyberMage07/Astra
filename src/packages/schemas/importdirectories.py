"""Schemas for PE delay-import and bound-import analysis."""

from pydantic import BaseModel, ConfigDict, Field


class DelayImportEntry(BaseModel):
    """One normalized PE delay-import symbol."""

    model_config = ConfigDict(frozen=True)

    library: str
    name: str | None = None
    ordinal: int | None = Field(default=None, ge=0)

    address: int = Field(ge=0)

    imported_by_name: bool = False
    imported_by_ordinal: bool = False

    suspicious: bool = False


class DelayImportLibrary(BaseModel):
    """One normalized PE delay-import library."""

    model_config = ConfigDict(frozen=True)

    library: str

    import_count: int = Field(default=0, ge=0)
    suspicious_import_count: int = Field(default=0, ge=0)

    imports: tuple[DelayImportEntry, ...] = ()


class BoundImportEntry(BaseModel):
    """One normalized PE bound-import descriptor."""

    model_config = ConfigDict(frozen=True)

    library: str

    timestamp: int = Field(default=0, ge=0)
    forwarder_count: int = Field(default=0, ge=0)

    malformed: bool = False


class ImportDirectoryAnalysisData(BaseModel):
    """Structured PE delay/bound import analysis output."""

    model_config = ConfigDict(frozen=True)

    delay_import_directory_present: bool
    bound_import_directory_present: bool

    delay_library_count: int = Field(default=0, ge=0)
    delay_import_count: int = Field(default=0, ge=0)
    suspicious_delay_import_count: int = Field(default=0, ge=0)

    bound_library_count: int = Field(default=0, ge=0)
    malformed_bound_import_count: int = Field(default=0, ge=0)

    delay_libraries: tuple[DelayImportLibrary, ...] = ()
    bound_imports: tuple[BoundImportEntry, ...] = ()
