"""Schemas for PE load-configuration analysis."""

from pydantic import BaseModel, ConfigDict, Field


class LoadConfigAnalysisData(BaseModel):
    """Structured PE load-configuration analysis output."""

    model_config = ConfigDict(frozen=True)

    load_config_present: bool

    size: int = Field(default=0, ge=0)
    timestamp: int = Field(default=0, ge=0)
    major_version: int = Field(default=0, ge=0)
    minor_version: int = Field(default=0, ge=0)

    security_cookie: int | None = Field(
        default=None,
        ge=0,
    )
    security_cookie_present: bool = False

    guard_flags: int = Field(default=0, ge=0)
    guard_flag_names: tuple[str, ...] = ()

    control_flow_guard_enabled: bool = False
    guard_cf_check_function: int | None = Field(
        default=None,
        ge=0,
    )
    guard_cf_dispatch_function: int | None = Field(
        default=None,
        ge=0,
    )
    guard_cf_function_table: int | None = Field(
        default=None,
        ge=0,
    )
    guard_cf_function_count: int = Field(
        default=0,
        ge=0,
    )

    seh_handler_table: int | None = Field(
        default=None,
        ge=0,
    )
    seh_handler_count: int = Field(
        default=0,
        ge=0,
    )
    safe_seh_present: bool = False
    safe_seh_applicable: bool = False

    dynamic_value_reloc_table: int | None = Field(
        default=None,
        ge=0,
    )
    code_integrity_present: bool = False

    malformed: bool = False
    invalid_pointer_count: int = Field(
        default=0,
        ge=0,
    )
