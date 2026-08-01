"""Schemas describing samples submitted to Astra."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class FileHashes(BaseModel):
    """Cryptographic hashes calculated for a sample."""

    model_config = ConfigDict(frozen=True)

    md5: str
    sha1: str
    sha256: str
    sha512: str


class SampleMetadata(BaseModel):
    """Normalized metadata for an ingested sample."""

    model_config = ConfigDict(frozen=True)

    sample_id: UUID = Field(default_factory=uuid4)
    original_name: str
    source_path: Path
    size_bytes: int = Field(ge=0)
    hashes: FileHashes
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
