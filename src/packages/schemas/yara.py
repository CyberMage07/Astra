"""Schemas for YARA analysis results."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class YaraStringMatch(BaseModel):
    """A single matched YARA string instance."""

    model_config = ConfigDict(frozen=True)

    identifier: str
    offset: int = Field(ge=0)
    matched_data: str


class YaraRuleMatch(BaseModel):
    """Normalized result for a matched YARA rule."""

    model_config = ConfigDict(frozen=True)

    rule: str
    namespace: str
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    strings: tuple[YaraStringMatch, ...] = ()
