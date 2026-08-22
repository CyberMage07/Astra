"""Schemas for ELF GNU symbol versioning and ABI dependency analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFSymbolVersionRequirement(BaseModel):
    """One required symbol-version dependency."""

    model_config = ConfigDict(frozen=True)

    library: str
    version: str

    version_index: int = Field(
        default=0,
        ge=0,
    )

    hidden: bool = False


class ELFSymbolVersionDefinition(BaseModel):
    """One symbol version defined by the ELF object."""

    model_config = ConfigDict(frozen=True)

    version: str

    version_index: int = Field(
        default=0,
        ge=0,
    )

    flags: int = Field(
        default=0,
        ge=0,
    )

    base: bool = False
    weak: bool = False


class ELFSymbolVersionBinding(BaseModel):
    """One dynamic symbol and its GNU version binding."""

    model_config = ConfigDict(frozen=True)

    symbol: str

    version: str | None = None

    version_index: int = Field(
        default=0,
        ge=0,
    )

    imported: bool = False
    exported: bool = False
    hidden: bool = False


class ELFVersioningAnalysisData(BaseModel):
    """Structured ELF GNU symbol-versioning analysis output."""

    model_config = ConfigDict(frozen=True)

    versioning_present: bool = False

    versym_present: bool = False
    verneed_present: bool = False
    verdef_present: bool = False

    required_library_count: int = Field(
        default=0,
        ge=0,
    )

    required_version_count: int = Field(
        default=0,
        ge=0,
    )

    defined_version_count: int = Field(
        default=0,
        ge=0,
    )

    versioned_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    imported_versioned_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    exported_versioned_symbol_count: int = Field(
        default=0,
        ge=0,
    )

    glibc_version_count: int = Field(
        default=0,
        ge=0,
    )

    glibcxx_version_count: int = Field(
        default=0,
        ge=0,
    )

    cxxabi_version_count: int = Field(
        default=0,
        ge=0,
    )

    highest_glibc_version: str | None = None
    highest_glibcxx_version: str | None = None
    highest_cxxabi_version: str | None = None

    malformed_entry_count: int = Field(
        default=0,
        ge=0,
    )

    requirements: tuple[
        ELFSymbolVersionRequirement,
        ...,
    ] = ()

    definitions: tuple[
        ELFSymbolVersionDefinition,
        ...,
    ] = ()

    bindings: tuple[
        ELFSymbolVersionBinding,
        ...,
    ] = ()
