"""Schemas for ELF symbol, import, and export analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFSymbolEntry(BaseModel):
    """One normalized ELF symbol."""

    model_config = ConfigDict(frozen=True)

    name: str

    value: int = Field(
        default=0,
        ge=0,
    )

    size: int = Field(
        default=0,
        ge=0,
    )

    binding: str
    symbol_type: str
    visibility: str

    section_index: str | int

    imported: bool = False
    exported: bool = False
    weak: bool = False

    suspicious: bool = False
    suspicious_category: str | None = None


class ELFSymbolAnalysisData(BaseModel):
    """Structured ELF symbol analysis output."""

    model_config = ConfigDict(frozen=True)

    symbol_tables_present: bool

    symbol_count: int = Field(
        default=0,
        ge=0,
    )

    dynamic_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    static_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    import_count: int = Field(
        default=0,
        ge=0,
    )

    export_count: int = Field(
        default=0,
        ge=0,
    )

    weak_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    suspicious_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    duplicate_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    stripped: bool = False

    symbols: tuple[ELFSymbolEntry, ...] = ()
