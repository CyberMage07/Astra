"""Schemas for PE debug-directory analysis."""

from pydantic import BaseModel, ConfigDict, Field


class DebugDirectoryEntry(BaseModel):
    """One normalized PE debug-directory entry."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)
    debug_type: int = Field(ge=0)
    debug_type_name: str

    timestamp: int = Field(ge=0)
    major_version: int = Field(ge=0)
    minor_version: int = Field(ge=0)

    size_of_data: int = Field(ge=0)
    address_of_raw_data: int = Field(ge=0)
    pointer_to_raw_data: int = Field(ge=0)

    signature: str | None = None
    pdb_path: str | None = None
    pdb_guid: str | None = None
    pdb_age: int | None = Field(default=None, ge=0)

    malformed: bool = False
    path_contains_username: bool = False
    path_is_absolute: bool = False
    path_is_network_share: bool = False


class DebugAnalysisData(BaseModel):
    """Structured PE debug-directory analysis output."""

    model_config = ConfigDict(frozen=True)

    debug_directory_present: bool

    entry_count: int = Field(default=0, ge=0)
    codeview_entry_count: int = Field(default=0, ge=0)
    reproducible_entry_count: int = Field(default=0, ge=0)

    malformed_entries: int = Field(default=0, ge=0)
    pdb_path_count: int = Field(default=0, ge=0)
    username_path_count: int = Field(default=0, ge=0)
    absolute_path_count: int = Field(default=0, ge=0)
    network_path_count: int = Field(default=0, ge=0)

    pdb_paths: tuple[str, ...] = ()
    entries: tuple[DebugDirectoryEntry, ...] = ()
