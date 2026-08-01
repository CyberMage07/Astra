"""Schemas for file-type identification results."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class FileTypeResult(BaseModel):
    """Normalized identification information for a submitted file."""

    model_config = ConfigDict(frozen=True)

    file_name: str
    extension: str
    mime_type: str
    magic_description: str
    detected_family: str
    extension_matches: bool | None
    is_executable: bool
    confidence: int = Field(ge=0, le=100)
    source_path: Path
