"""Schemas for ELF fingerprint and clustering analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFFingerprintSource(BaseModel):
    """One normalized ELF fingerprint source."""

    model_config = ConfigDict(frozen=True)

    name: str

    item_count: int = Field(
        default=0,
        ge=0,
    )

    normalized_source: str

    sha256: str = Field(
        min_length=64,
        max_length=64,
    )


class ELFFingerprintAnalysisData(BaseModel):
    """Structured ELF fingerprint analysis output."""

    model_config = ConfigDict(frozen=True)

    fingerprint_available: bool

    import_fingerprint: str | None = None
    library_fingerprint: str | None = None
    section_fingerprint: str | None = None
    combined_fingerprint: str | None = None

    build_id: str | None = None

    imported_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    needed_library_count: int = Field(
        default=0,
        ge=0,
    )

    section_count: int = Field(
        default=0,
        ge=0,
    )

    source_count: int = Field(
        default=0,
        ge=0,
    )

    sources: tuple[
        ELFFingerprintSource,
        ...,
    ] = ()
