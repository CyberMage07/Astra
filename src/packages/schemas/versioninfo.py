"""Schemas for PE version-information analysis."""

from pydantic import BaseModel, ConfigDict, Field


class VersionStringEntry(BaseModel):
    """One normalized PE version-information string."""

    model_config = ConfigDict(frozen=True)

    key: str = Field(min_length=1)
    value: str
    language: str | None = None
    code_page: str | None = None


class VersionInfoAnalysisData(BaseModel):
    """Structured PE version-information analysis output."""

    model_config = ConfigDict(frozen=True)

    version_info_present: bool

    company_name: str | None = None
    file_description: str | None = None
    file_version: str | None = None
    internal_name: str | None = None
    legal_copyright: str | None = None
    original_filename: str | None = None
    product_name: str | None = None
    product_version: str | None = None

    language: str | None = None
    code_page: str | None = None

    string_count: int = Field(default=0, ge=0)
    strings: tuple[VersionStringEntry, ...] = ()

    original_filename_matches: bool | None = None
    suspicious_company_name: bool = False
    suspicious_product_name: bool = False
    missing_identity_fields: bool = False
