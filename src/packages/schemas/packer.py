"""Schemas for packer detection results."""

from pydantic import BaseModel, ConfigDict, Field

from packages.schemas.analysis import Severity


class PackerIndicator(BaseModel):
    """A single piece of evidence suggesting packing or protection."""

    model_config = ConfigDict(frozen=True)

    indicator_type: str
    description: str
    value: str
    confidence: int = Field(ge=0, le=100)
    severity: Severity
    location: str | None = None


class PackerCandidate(BaseModel):
    """A possible packer identified from accumulated evidence."""

    model_config = ConfigDict(frozen=True)

    name: str
    confidence: int = Field(ge=0, le=100)
    indicators: tuple[PackerIndicator, ...] = ()


class PackerAnalysisData(BaseModel):
    """Structured packer-detection analysis."""

    model_config = ConfigDict(frozen=True)

    is_likely_packed: bool
    confidence: int = Field(ge=0, le=100)
    detected_packer: str | None = None
    candidates: tuple[PackerCandidate, ...] = ()
    indicators: tuple[PackerIndicator, ...] = ()
    high_entropy_sections: int = Field(default=0, ge=0)
    executable_writable_sections: int = Field(default=0, ge=0)
    suspicious_section_names: int = Field(default=0, ge=0)
    import_count: int = Field(default=0, ge=0)
    overlay_size: int = Field(default=0, ge=0)
