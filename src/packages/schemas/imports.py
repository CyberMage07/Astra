"""Schemas for suspicious import and behavior analysis."""

from pydantic import BaseModel, ConfigDict, Field

from packages.schemas.analysis import Severity


class ImportIndicator(BaseModel):
    """A classified imported API."""

    model_config = ConfigDict(frozen=True)

    library: str
    function: str
    category: str
    description: str
    severity: Severity
    weight: int = Field(ge=0, le=100)
    attack_techniques: tuple[str, ...] = ()


class ImportBehaviorSummary(BaseModel):
    """Grouped suspicious import behavior."""

    model_config = ConfigDict(frozen=True)

    category: str
    count: int = Field(ge=0)
    maximum_severity: Severity
    indicators: tuple[ImportIndicator, ...] = ()


class ImportAnalysisData(BaseModel):
    """Structured suspicious import analysis."""

    model_config = ConfigDict(frozen=True)

    total_imports: int = Field(ge=0)
    suspicious_imports: int = Field(ge=0)
    behaviors: tuple[ImportBehaviorSummary, ...] = ()
    indicators: tuple[ImportIndicator, ...] = ()
