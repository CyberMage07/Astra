"""Schemas for PE application-manifest analysis."""

from pydantic import BaseModel, ConfigDict, Field


class ManifestDependency(BaseModel):
    """One normalized manifest dependency."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str | None = None
    processor_architecture: str | None = None
    public_key_token: str | None = None
    language: str | None = None
    dependency_type: str | None = None


class ManifestAnalysisData(BaseModel):
    """Structured Windows PE manifest analysis output."""

    model_config = ConfigDict(frozen=True)

    manifest_present: bool

    manifest_count: int = Field(default=0, ge=0)

    requested_execution_level: str | None = None
    ui_access: bool | None = None

    requires_administrator: bool = False
    highest_available: bool = False
    as_invoker: bool = False

    auto_elevate: bool = False

    dpi_aware: bool | None = None
    long_path_aware: bool | None = None

    supported_os_count: int = Field(default=0, ge=0)
    supported_os_ids: tuple[str, ...] = ()

    dependency_count: int = Field(default=0, ge=0)
    dependencies: tuple[ManifestDependency, ...] = ()

    requested_privileges_present: bool = False

    malformed: bool = False

    raw_manifest_count: int = Field(default=0, ge=0)
