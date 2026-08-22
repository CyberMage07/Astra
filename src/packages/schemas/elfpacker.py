"""Schemas for ELF packer and obfuscation analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ELFPackerIndicator(BaseModel):
    """One normalized ELF packing or obfuscation indicator."""

    model_config = ConfigDict(frozen=True)

    name: str
    category: str
    description: str

    weight: int = Field(
        ge=0,
        le=100,
    )

    triggered: bool = False

    evidence: tuple[str, ...] = ()


class ELFPackerAnalysisData(BaseModel):
    """Structured ELF packer and obfuscation analysis output."""

    model_config = ConfigDict(frozen=True)

    packed_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    packed_likelihood: str

    suspected_packer: str | None = None
    known_packer_signature: bool = False

    high_entropy_section_count: int = Field(
        default=0,
        ge=0,
    )

    executable_high_entropy_count: int = Field(
        default=0,
        ge=0,
    )

    rwx_section_count: int = Field(
        default=0,
        ge=0,
    )

    suspicious_section_name_count: int = Field(
        default=0,
        ge=0,
    )

    stripped: bool = False
    symbol_table_present: bool = False

    import_count: int = Field(
        default=0,
        ge=0,
    )

    relocation_count: int = Field(
        default=0,
        ge=0,
    )

    unusual_entry_point: bool = False
    suspicious_dynamic_loading: bool = False
    suspicious_layout: bool = False

    evidence_count: int = Field(
        default=0,
        ge=0,
    )

    indicators: tuple[
        ELFPackerIndicator,
        ...,
    ] = ()
