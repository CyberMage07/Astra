"""Schemas for recursive embedded-payload analysis."""

from pydantic import BaseModel, ConfigDict, Field


class EmbeddedPayloadLocation(BaseModel):
    """Location information for one embedded payload."""

    model_config = ConfigDict(frozen=True)

    source: str

    offset: int | None = Field(
        default=None,
        ge=0,
    )

    size: int = Field(
        ge=0,
    )

    resource_type: str | None = None
    resource_name: str | None = None

    parent_section: str | None = None


class EmbeddedPayloadIdentity(BaseModel):
    """File identity information for an embedded payload."""

    model_config = ConfigDict(frozen=True)

    sha256: str

    detected_family: str
    mime_type: str
    magic_description: str

    extension: str | None = None

    is_executable: bool = False


class EmbeddedPayloadAnalysisSummary(BaseModel):
    """Condensed recursive-analysis result for one child payload."""

    model_config = ConfigDict(frozen=True)

    analyzed: bool = False

    analyzer_count: int = Field(
        default=0,
        ge=0,
    )

    completed_analyzers: int = Field(
        default=0,
        ge=0,
    )

    failed_analyzers: int = Field(
        default=0,
        ge=0,
    )

    finding_count: int = Field(
        default=0,
        ge=0,
    )

    classification: str | None = None

    risk_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    confidence: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )


class EmbeddedPayloadEntry(BaseModel):
    """One normalized embedded payload."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(
        ge=0,
    )

    parent_index: int | None = Field(
        default=None,
        ge=0,
    )
    depth: int = Field(
        ge=1,
    )

    location: EmbeddedPayloadLocation
    identity: EmbeddedPayloadIdentity

    entropy: float | None = Field(
        default=None,
        ge=0.0,
        le=8.0,
    )

    extraction_method: str

    duplicate: bool = False
    truncated: bool = False

    analysis: EmbeddedPayloadAnalysisSummary = EmbeddedPayloadAnalysisSummary()


class EmbeddedAnalysisLimits(BaseModel):
    """Safety limits applied to recursive payload analysis."""

    model_config = ConfigDict(frozen=True)

    maximum_depth: int = Field(
        default=3,
        ge=1,
    )

    maximum_payloads: int = Field(
        default=64,
        ge=1,
    )

    maximum_payload_size: int = Field(
        default=64 * 1024 * 1024,
        ge=1,
    )

    maximum_total_extracted_bytes: int = Field(
        default=256 * 1024 * 1024,
        ge=1,
    )


class EmbeddedAnalysisData(BaseModel):
    """Structured recursive embedded-payload analysis output."""

    model_config = ConfigDict(frozen=True)

    embedded_payloads_present: bool

    payload_count: int = Field(
        default=0,
        ge=0,
    )

    analyzed_payload_count: int = Field(
        default=0,
        ge=0,
    )

    executable_payload_count: int = Field(
        default=0,
        ge=0,
    )

    archive_payload_count: int = Field(
        default=0,
        ge=0,
    )

    document_payload_count: int = Field(
        default=0,
        ge=0,
    )

    script_payload_count: int = Field(
        default=0,
        ge=0,
    )

    duplicate_payload_count: int = Field(
        default=0,
        ge=0,
    )

    skipped_payload_count: int = Field(
        default=0,
        ge=0,
    )

    maximum_depth_reached: int = Field(
        default=0,
        ge=0,
    )

    total_extracted_bytes: int = Field(
        default=0,
        ge=0,
    )

    recursion_limit_reached: bool = False
    payload_limit_reached: bool = False
    byte_limit_reached: bool = False

    limits: EmbeddedAnalysisLimits = EmbeddedAnalysisLimits()

    payloads: tuple[EmbeddedPayloadEntry, ...] = ()
