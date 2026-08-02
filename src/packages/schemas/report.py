"""Schemas for unified Astra analysis reports."""

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from packages.schemas.analysis import AnalysisResult, Finding
from packages.schemas.filetype import FileTypeResult
from packages.schemas.sample import FileHashes


class ThreatClassification(StrEnum):
    """Normalized high-level threat classification."""

    LIKELY_BENIGN = "likely-benign"
    LOW_RISK = "low-risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high-risk"
    HIGHLY_SUSPICIOUS = "highly-suspicious"


class AnalyzerExecution(BaseModel):
    """Execution summary for one analyzer."""

    model_config = ConfigDict(frozen=True)

    analyzer: str
    status: str
    duration_ms: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    error_count: int = Field(ge=0)


class ThreatAssessment(BaseModel):
    """Aggregated threat assessment for a sample."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    classification: ThreatClassification
    confidence: int = Field(ge=0, le=100)
    reasons: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()


class AnalysisReport(BaseModel):
    """Unified report produced by Astra's analysis pipeline."""

    model_config = ConfigDict(frozen=True)

    report_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    sample_path: Path
    original_name: str
    size_bytes: int = Field(ge=0)
    hashes: FileHashes
    file_type: FileTypeResult

    analyzer_results: tuple[AnalysisResult, ...] = ()
    analyzer_executions: tuple[AnalyzerExecution, ...] = ()
    findings: tuple[Finding, ...] = ()

    assessment: ThreatAssessment | None = None
    completed_analyzers: int = Field(default=0, ge=0)
    failed_analyzers: int = Field(default=0, ge=0)
    total_duration_ms: int = Field(default=0, ge=0)
