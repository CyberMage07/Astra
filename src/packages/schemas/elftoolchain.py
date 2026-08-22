"""Schemas for ELF compiler, toolchain, and build provenance analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFToolchainMarker(BaseModel):
    """One normalized compiler, linker, runtime, or build marker."""

    model_config = ConfigDict(frozen=True)

    category: str
    value: str
    source: str

    confidence: int = Field(
        default=50,
        ge=0,
        le=100,
    )


class ELFToolchainAnalysisData(BaseModel):
    """Structured ELF compiler and build provenance analysis output."""

    model_config = ConfigDict(frozen=True)

    toolchain_detected: bool = False

    primary_compiler: str | None = None
    compiler_version: str | None = None

    linker: str | None = None
    linker_version: str | None = None

    language: str | None = None
    runtime: str | None = None

    gcc_detected: bool = False
    clang_detected: bool = False
    rust_detected: bool = False
    go_detected: bool = False

    lto_detected: bool = False

    comment_section_present: bool = False
    comment_entry_count: int = Field(
        default=0,
        ge=0,
    )

    build_id: str | None = None

    compiler_marker_count: int = Field(
        default=0,
        ge=0,
    )

    linker_marker_count: int = Field(
        default=0,
        ge=0,
    )

    runtime_marker_count: int = Field(
        default=0,
        ge=0,
    )

    language_marker_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_entry_count: int = Field(
        default=0,
        ge=0,
    )

    markers: tuple[
        ELFToolchainMarker,
        ...,
    ] = ()
