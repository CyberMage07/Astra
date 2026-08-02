"""Schemas for PE digital-signature analysis."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SignatureStatus(StrEnum):
    """Normalized digital-signature status."""

    UNSIGNED = "unsigned"
    PRESENT = "present"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class CertificateInfo(BaseModel):
    """Normalized signer-certificate information."""

    model_config = ConfigDict(frozen=True)

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    thumbprint_sha1: str | None = None
    thumbprint_sha256: str | None = None

    valid_from: datetime | None = None
    valid_until: datetime | None = None

    is_expired: bool = False
    is_self_signed: bool = False


class SignatureAnalysisData(BaseModel):
    """Structured PE signature-analysis output."""

    model_config = ConfigDict(frozen=True)

    status: SignatureStatus
    is_signed: bool = False
    signature_present: bool = False
    signature_valid: bool | None = None
    trust_verified: bool | None = None

    signer_count: int = Field(default=0, ge=0)
    certificates: tuple[CertificateInfo, ...] = ()

    digest_algorithm: str | None = None
    timestamp_present: bool = False
    timestamp: datetime | None = None

    verification_error: str | None = None
