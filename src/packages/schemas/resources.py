"""Schemas for PE resource analysis."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ResourceType(StrEnum):
    """Known Windows PE resource types."""

    CURSOR = "cursor"
    BITMAP = "bitmap"
    ICON = "icon"
    MENU = "menu"
    DIALOG = "dialog"
    STRING = "string"
    FONT_DIRECTORY = "font-directory"
    FONT = "font"
    ACCELERATOR = "accelerator"
    RCDATA = "rcdata"
    MESSAGE_TABLE = "message-table"
    GROUP_CURSOR = "group-cursor"
    GROUP_ICON = "group-icon"
    VERSION = "version"
    HTML = "html"
    MANIFEST = "manifest"
    UNKNOWN = "unknown"


class ResourceEntry(BaseModel):
    """Normalized information for one embedded PE resource."""

    model_config = ConfigDict(frozen=True)

    resource_type: ResourceType
    type_name: str
    name: str | None = None
    language: str | None = None

    rva: int = Field(ge=0)
    offset: int = Field(ge=0)
    size: int = Field(ge=0)

    entropy: float = Field(ge=0.0, le=8.0)
    sha256: str = Field(min_length=64, max_length=64)

    is_executable: bool = False
    embedded_file_type: str | None = None
    is_high_entropy: bool = False


class ResourceAnalysisData(BaseModel):
    """Structured PE resource-analysis output."""

    model_config = ConfigDict(frozen=True)

    resource_count: int = Field(ge=0)
    resources: tuple[ResourceEntry, ...] = ()

    icon_count: int = Field(default=0, ge=0)
    manifest_count: int = Field(default=0, ge=0)
    version_count: int = Field(default=0, ge=0)
    rcdata_count: int = Field(default=0, ge=0)

    high_entropy_resources: int = Field(default=0, ge=0)
    embedded_executables: int = Field(default=0, ge=0)
    embedded_archives: int = Field(default=0, ge=0)
    embedded_documents: int = Field(default=0, ge=0)

    total_resource_bytes: int = Field(default=0, ge=0)
    largest_resource_size: int = Field(default=0, ge=0)
