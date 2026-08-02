"""Schemas for entropy analysis results."""

from pydantic import BaseModel, ConfigDict, Field


class EntropyRegion(BaseModel):
    """Entropy measurement for a region of a sample."""

    model_config = ConfigDict(frozen=True)

    offset: int = Field(ge=0)
    size: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)


class EntropyAnalysisData(BaseModel):
    """Structured entropy information for a sample."""

    model_config = ConfigDict(frozen=True)

    overall_entropy: float = Field(ge=0.0, le=8.0)
    file_size: int = Field(ge=0)
    block_size: int = Field(ge=1)
    regions: tuple[EntropyRegion, ...] = ()
    high_entropy_regions: int = Field(ge=0)
    maximum_region_entropy: float = Field(ge=0.0, le=8.0)
