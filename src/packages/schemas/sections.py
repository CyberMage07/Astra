"""Schemas for PE section analysis."""

from pydantic import BaseModel, ConfigDict, Field


class SectionInfo(BaseModel):
    """Normalized PE section information."""

    model_config = ConfigDict(frozen=True)

    name: str
    virtual_address: int = Field(ge=0)
    virtual_size: int = Field(ge=0)
    raw_offset: int = Field(ge=0)
    raw_size: int = Field(ge=0)

    entropy: float = Field(ge=0.0, le=8.0)
    characteristics: int = Field(ge=0)

    readable: bool
    writable: bool
    executable: bool

    is_rwx: bool = False
    is_wx: bool = False
    is_empty: bool = False
    has_virtual_raw_anomaly: bool = False
    is_suspicious_name: bool = False
    is_executable_resource: bool = False


class SectionAnalysisData(BaseModel):
    """Structured PE section-analysis output."""

    model_config = ConfigDict(frozen=True)

    section_count: int = Field(ge=0)
    sections: tuple[SectionInfo, ...] = ()

    high_entropy_sections: int = Field(default=0, ge=0)
    executable_sections: int = Field(default=0, ge=0)
    writable_sections: int = Field(default=0, ge=0)
    rwx_sections: int = Field(default=0, ge=0)
    wx_sections: int = Field(default=0, ge=0)

    suspicious_name_sections: int = Field(default=0, ge=0)
    empty_executable_sections: int = Field(default=0, ge=0)
    virtual_raw_anomalies: int = Field(default=0, ge=0)
    executable_resource_sections: int = Field(default=0, ge=0)
