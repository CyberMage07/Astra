"""Schemas for normalized file metadata analysis."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MetadataSource(StrEnum):
    """Supported metadata sources."""

    PE_VERSION_INFO = "pe-version-info"
    PE_HEADER = "pe-header"
    PDF_DOCUMENT_INFO = "pdf-document-info"
    OFFICE_PROPERTIES = "office-properties"
    APK_MANIFEST = "apk-manifest"
    ARCHIVE = "archive"
    FILE_SYSTEM = "file-system"


class MetadataEntry(BaseModel):
    """A normalized metadata field extracted from a sample."""

    model_config = ConfigDict(frozen=True)

    key: str
    value: str
    source: MetadataSource
    confidence: int = Field(default=100, ge=0, le=100)


class MetadataAnalysisData(BaseModel):
    """Structured metadata-analysis output."""

    model_config = ConfigDict(frozen=True)

    entries: tuple[MetadataEntry, ...] = ()
    entry_count: int = Field(default=0, ge=0)

    company_name: str | None = None
    product_name: str | None = None
    file_description: str | None = None
    original_filename: str | None = None
    internal_name: str | None = None
    product_version: str | None = None
    file_version: str | None = None
    legal_copyright: str | None = None
    language: str | None = None

    compile_timestamp: int | None = Field(default=None, ge=0)
    compile_datetime: datetime | None = None

    has_version_info: bool = False
    suspicious_timestamp: bool = False
    future_timestamp: bool = False
