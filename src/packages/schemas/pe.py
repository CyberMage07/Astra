"""Schemas for Windows Portable Executable analysis."""

from pydantic import BaseModel, ConfigDict, Field


class PESection(BaseModel):
    """Normalized PE section information."""

    model_config = ConfigDict(frozen=True)

    name: str
    virtual_address: int = Field(ge=0)
    virtual_size: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)
    characteristics: int = Field(ge=0)
    executable: bool
    writable: bool
    readable: bool


class PEImport(BaseModel):
    """Imported function from a PE library."""

    model_config = ConfigDict(frozen=True)

    library: str
    function: str
    address: int | None = Field(default=None, ge=0)
    ordinal: int | None = Field(default=None, ge=0)


class PEExport(BaseModel):
    """Exported PE symbol."""

    model_config = ConfigDict(frozen=True)

    name: str | None = None
    ordinal: int = Field(ge=0)
    address: int = Field(ge=0)


class PEHeaderInfo(BaseModel):
    """Core PE header information."""

    model_config = ConfigDict(frozen=True)

    machine: str
    architecture_bits: int
    subsystem: str
    image_base: int = Field(ge=0)
    entry_point: int = Field(ge=0)
    compile_timestamp: int = Field(ge=0)
    number_of_sections: int = Field(ge=0)
    characteristics: int = Field(ge=0)
    is_dll: bool
    is_driver: bool


class PEAnalysisData(BaseModel):
    """Structured data extracted from a PE sample."""

    model_config = ConfigDict(frozen=True)

    header: PEHeaderInfo
    sections: tuple[PESection, ...] = ()
    imports: tuple[PEImport, ...] = ()
    exports: tuple[PEExport, ...] = ()
    overlay_size: int = Field(default=0, ge=0)
    has_tls_callbacks: bool = False
    has_debug_directory: bool = False
    has_resources: bool = False
    signed: bool = False
