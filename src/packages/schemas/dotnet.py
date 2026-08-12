"""Schemas for .NET CLR and managed-metadata analysis."""

from pydantic import BaseModel, ConfigDict, Field


class DotNetStreamInfo(BaseModel):
    """One normalized .NET metadata stream."""

    model_config = ConfigDict(frozen=True)

    name: str
    offset: int = Field(ge=0)
    size: int = Field(ge=0)


class DotNetAssemblyReference(BaseModel):
    """One normalized .NET assembly reference."""

    model_config = ConfigDict(frozen=True)

    name: str

    major_version: int = Field(default=0, ge=0)
    minor_version: int = Field(default=0, ge=0)
    build_number: int = Field(default=0, ge=0)
    revision_number: int = Field(default=0, ge=0)

    culture: str | None = None

    version: str | None = None


class DotNetAnalysisData(BaseModel):
    """Structured .NET CLR analysis output."""

    model_config = ConfigDict(frozen=True)

    dotnet_present: bool

    clr_header_present: bool = False
    metadata_present: bool = False
    clr_header_size: int = Field(
        default=0,
        ge=0,
    )

    runtime_version: str | None = None

    clr_flags: int = Field(default=0, ge=0)
    clr_flag_names: tuple[str, ...] = ()

    il_only: bool = False
    thirty_two_bit_required: bool = False
    thirty_two_bit_preferred: bool = False
    strong_name_signed: bool = False
    native_entry_point: bool = False

    mixed_mode: bool = False

    entry_point_token: int | None = Field(
        default=None,
        ge=0,
    )
    entry_point_rva: int | None = Field(
        default=None,
        ge=0,
    )

    metadata_signature: int | None = Field(
        default=None,
        ge=0,
    )

    metadata_version: str | None = None

    stream_count: int = Field(default=0, ge=0)
    streams: tuple[DotNetStreamInfo, ...] = ()

    assembly_name: str | None = None
    assembly_version: str | None = None
    assembly_culture: str | None = None

    module_name: str | None = None

    assembly_reference_count: int = Field(
        default=0,
        ge=0,
    )
    assembly_references: tuple[DotNetAssemblyReference, ...] = ()

    type_definition_count: int = Field(
        default=0,
        ge=0,
    )
    method_definition_count: int = Field(
        default=0,
        ge=0,
    )
    member_reference_count: int = Field(
        default=0,
        ge=0,
    )

    pinvoke_method_count: int = Field(
        default=0,
        ge=0,
    )

    malformed_metadata: bool = False
