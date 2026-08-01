"""Common schemas for Astra analysis results."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class AnalysisStatus(StrEnum):
    """Execution status for an analyzer."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(StrEnum):
    """Normalized severity assigned to findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """Evidence supporting an analyzer finding."""

    model_config = ConfigDict(frozen=True)

    kind: str
    value: str
    location: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Normalized security finding produced by an analyzer."""

    model_config = ConfigDict(frozen=True)

    finding_id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    category: str
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    evidence: tuple[Evidence, ...] = ()
    tags: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()


class AnalyzerError(BaseModel):
    """Structured analyzer execution error."""

    model_config = ConfigDict(frozen=True)

    error_type: str
    message: str
    recoverable: bool = True


class AnalysisResult(BaseModel):
    """Standard result returned by every Astra analyzer."""

    model_config = ConfigDict(frozen=True)

    analyzer: str
    analyzer_version: str
    status: AnalysisStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = Field(ge=0)
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[str, ...] = ()
    data: dict[str, Any] = Field(default_factory=dict)
    errors: tuple[AnalyzerError, ...] = ()
