"""Schemas for extracted strings."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StringEncoding(StrEnum):
    """Supported string encodings."""

    ASCII = "ascii"
    UTF16_LE = "utf-16-le"
    UTF16_BE = "utf-16-be"


class ExtractedString(BaseModel):
    """A string extracted from a sample."""

    model_config = ConfigDict(frozen=True)

    value: str
    offset: int = Field(ge=0)
    encoding: StringEncoding
    length: int = Field(ge=1)


class StringsAnalysisData(BaseModel):
    """Normalized strings-analysis output."""

    model_config = ConfigDict(frozen=True)

    strings: tuple[ExtractedString, ...] = ()
    total_count: int = Field(ge=0)
    truncated: bool = False
    minimum_length: int = Field(ge=1)
