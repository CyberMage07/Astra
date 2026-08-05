"""Schemas for PE overlay analysis."""

from pydantic import BaseModel, ConfigDict, Field


class OverlayAnalysisData(BaseModel):
    """Structured PE overlay-analysis output."""

    model_config = ConfigDict(frozen=True)

    overlay_present: bool

    offset: int | None = Field(default=None, ge=0)
    size: int = Field(default=0, ge=0)
    percentage_of_file: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    entropy: float = Field(
        default=0.0,
        ge=0.0,
        le=8.0,
    )

    sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )

    embedded_file_type: str | None = None
    is_executable: bool = False
    is_archive: bool = False
    is_document: bool = False
    is_script: bool = False

    is_high_entropy: bool = False
    is_large: bool = False
    is_certificate_table: bool = False
    is_installer_payload: bool = False
    installer_type: str | None = None
