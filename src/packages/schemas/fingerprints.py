"""Schemas for PE fingerprint and import-hash analysis."""

from pydantic import BaseModel, ConfigDict, Field


class FingerprintImport(BaseModel):
    """One normalized import used for fingerprint generation."""

    model_config = ConfigDict(frozen=True)

    library: str
    symbol: str | None = None
    ordinal: int | None = Field(
        default=None,
        ge=0,
    )

    imported_by_name: bool = False
    imported_by_ordinal: bool = False

    normalized: str


class FingerprintLibrary(BaseModel):
    """One normalized imported library and its fingerprint entries."""

    model_config = ConfigDict(frozen=True)

    name: str

    import_count: int = Field(
        default=0,
        ge=0,
    )

    named_import_count: int = Field(
        default=0,
        ge=0,
    )

    ordinal_import_count: int = Field(
        default=0,
        ge=0,
    )

    imports: tuple[FingerprintImport, ...] = ()


class FingerprintAnalysisData(BaseModel):
    """Structured PE fingerprint-analysis output."""

    model_config = ConfigDict(frozen=True)

    fingerprint_available: bool

    imphash: str | None = None

    import_library_count: int = Field(
        default=0,
        ge=0,
    )

    import_count: int = Field(
        default=0,
        ge=0,
    )

    named_import_count: int = Field(
        default=0,
        ge=0,
    )

    ordinal_import_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_import_count: int = Field(
        default=0,
        ge=0,
    )

    fingerprint_source: str | None = None

    libraries: tuple[FingerprintLibrary, ...] = ()

    # Reserved for future enterprise fingerprint expansion.
    rich_header_hash: str | None = None
    section_hash: str | None = None
    authentihash: str | None = None
    tlsh: str | None = None
    ssdeep: str | None = None
