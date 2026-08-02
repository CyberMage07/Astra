"""Schemas for indicator-of-compromise extraction."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IOCType(StrEnum):
    """Supported indicator types."""

    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    EMAIL = "email"
    REGISTRY_PATH = "registry-path"
    WINDOWS_PATH = "windows-path"
    UNC_PATH = "unc-path"
    POWERSHELL = "powershell"
    CMD = "cmd"
    BASE64 = "base64"


class IOCIndicator(BaseModel):
    """A normalized indicator extracted from a sample."""

    model_config = ConfigDict(frozen=True)

    indicator_type: IOCType
    value: str
    source_string: str
    offset: int | None = Field(default=None, ge=0)
    confidence: int = Field(ge=0, le=100)
    tags: tuple[str, ...] = ()


class IOCSummary(BaseModel):
    """Summary for one IOC category."""

    model_config = ConfigDict(frozen=True)

    indicator_type: IOCType
    count: int = Field(ge=0)
    indicators: tuple[IOCIndicator, ...] = ()


class IOCAnalysisData(BaseModel):
    """Structured IOC extraction results."""

    model_config = ConfigDict(frozen=True)

    total_indicators: int = Field(ge=0)
    unique_indicators: int = Field(ge=0)
    summaries: tuple[IOCSummary, ...] = ()
    indicators: tuple[IOCIndicator, ...] = ()
