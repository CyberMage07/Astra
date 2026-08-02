"""PE digital-signature and certificate analysis for Astra."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    CertificateInfo,
    Evidence,
    Finding,
    Severity,
    SignatureAnalysisData,
    SignatureStatus,
)

WIN_CERTIFICATE_HEADER_SIZE = 8
WIN_CERTIFICATE_REVISION_2_0 = 0x0200
WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA = 0x0002


def _certificate_name(
    name: x509.Name,
) -> str:
    """Return a readable X.509 distinguished name."""
    return name.rfc4514_string()


def _certificate_datetime(
    value: datetime,
) -> datetime:
    """Normalize certificate timestamps to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)

    return value.astimezone(UTC)


def _certificate_thumbprint(
    certificate: x509.Certificate,
    algorithm: hashes.HashAlgorithm,
) -> str:
    """Calculate a certificate fingerprint."""
    return certificate.fingerprint(algorithm).hex()


def _is_self_signed(
    certificate: x509.Certificate,
) -> bool:
    """Return whether certificate subject and issuer are identical."""
    return certificate.subject == certificate.issuer


def _certificate_info(
    certificate: x509.Certificate,
    now: datetime,
) -> CertificateInfo:
    """Normalize one parsed certificate."""
    valid_from = _certificate_datetime(certificate.not_valid_before_utc)
    valid_until = _certificate_datetime(certificate.not_valid_after_utc)

    return CertificateInfo(
        subject=_certificate_name(certificate.subject),
        issuer=_certificate_name(certificate.issuer),
        serial_number=f"{certificate.serial_number:x}",
        thumbprint_sha1=_certificate_thumbprint(
            certificate,
            hashes.SHA1(),
        ),
        thumbprint_sha256=_certificate_thumbprint(
            certificate,
            hashes.SHA256(),
        ),
        valid_from=valid_from,
        valid_until=valid_until,
        is_expired=valid_until < now,
        is_self_signed=_is_self_signed(certificate),
    )


def _security_directory(
    pe: pefile.PE,
) -> tuple[int, int]:
    """Return the Authenticode security-directory file offset and size."""
    directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY

    if directory_index >= len(directories):
        return 0, 0

    directory = directories[directory_index]

    return int(directory.VirtualAddress), int(directory.Size)


def _extract_pkcs7_blob(
    sample_data: bytes,
    offset: int,
    size: int,
) -> bytes | None:
    """Extract PKCS#7 content from a WIN_CERTIFICATE structure."""
    if offset <= 0 or size < WIN_CERTIFICATE_HEADER_SIZE:
        return None

    certificate_end = min(
        len(sample_data),
        offset + size,
    )

    if offset + WIN_CERTIFICATE_HEADER_SIZE > certificate_end:
        return None

    certificate_length = int.from_bytes(
        sample_data[offset : offset + 4],
        byteorder="little",
    )
    revision = int.from_bytes(
        sample_data[offset + 4 : offset + 6],
        byteorder="little",
    )
    certificate_type = int.from_bytes(
        sample_data[offset + 6 : offset + 8],
        byteorder="little",
    )

    if certificate_length < WIN_CERTIFICATE_HEADER_SIZE:
        return None

    if revision != WIN_CERTIFICATE_REVISION_2_0:
        return None

    if certificate_type != WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA:
        return None

    payload_end = min(
        certificate_end,
        offset + certificate_length,
    )

    payload = sample_data[offset + WIN_CERTIFICATE_HEADER_SIZE : payload_end]

    return payload or None


def _load_certificates(
    pkcs7_blob: bytes,
) -> tuple[x509.Certificate, ...]:
    """Load embedded certificates from Authenticode PKCS#7 data."""
    certificates = pkcs7.load_der_pkcs7_certificates(pkcs7_blob)

    return tuple(certificates)


def _digest_algorithm(
    pkcs7_blob: bytes,
) -> str:
    """Return a deterministic identifier for the PKCS#7 payload.

    Full Authenticode digest-algorithm parsing will be added with
    cryptographic signature verification.
    """
    return f"pkcs7-sha256:{hashlib.sha256(pkcs7_blob).hexdigest()}"


def _status_from_certificates(
    *,
    signature_present: bool,
    certificates: tuple[CertificateInfo, ...],
) -> SignatureStatus:
    """Determine a conservative signature-analysis status."""
    if not signature_present:
        return SignatureStatus.UNSIGNED

    if not certificates:
        return SignatureStatus.PRESENT

    if all(certificate.is_expired for certificate in certificates):
        return SignatureStatus.EXPIRED

    return SignatureStatus.PRESENT


def _build_findings(
    data: SignatureAnalysisData,
) -> tuple[Finding, ...]:
    """Generate findings from signature and certificate properties."""
    findings: list[Finding] = []

    if not data.signature_present:
        findings.append(
            Finding(
                title="PE file is unsigned",
                description=("The executable does not contain an Authenticode security directory."),
                category="digital-signature",
                severity=Severity.INFO,
                confidence=100,
                evidence=(
                    Evidence(
                        kind="signature-status",
                        value="unsigned",
                        location="PE security directory",
                    ),
                ),
                tags=("pe", "signature", "unsigned"),
            )
        )

        return tuple(findings)

    expired_certificates = tuple(
        certificate for certificate in data.certificates if certificate.is_expired
    )

    if expired_certificates:
        findings.append(
            Finding(
                title="Expired signing certificate detected",
                description=(
                    "One or more certificates embedded in the PE "
                    "signature are past their validity period."
                ),
                category="digital-signature",
                severity=Severity.LOW,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="certificate",
                        value=certificate.subject or "unknown subject",
                        location="Authenticode PKCS#7",
                        metadata={
                            "issuer": certificate.issuer,
                            "valid_until": (
                                certificate.valid_until.isoformat()
                                if certificate.valid_until is not None
                                else None
                            ),
                        },
                    )
                    for certificate in expired_certificates[:10]
                ),
                tags=("pe", "signature", "certificate", "expired"),
            )
        )

    self_signed_certificates = tuple(
        certificate for certificate in data.certificates if certificate.is_self_signed
    )

    if self_signed_certificates:
        findings.append(
            Finding(
                title="Self-signed certificate detected",
                description=(
                    "The PE signature contains one or more self-signed "
                    "certificates. Trust has not been established."
                ),
                category="digital-signature",
                severity=Severity.LOW,
                confidence=75,
                evidence=tuple(
                    Evidence(
                        kind="certificate",
                        value=certificate.subject or "unknown subject",
                        location="Authenticode PKCS#7",
                    )
                    for certificate in self_signed_certificates[:10]
                ),
                tags=("pe", "signature", "certificate", "self-signed"),
            )
        )

    return tuple(findings)


class SignatureAnalyzer:
    """Analyze PE Authenticode signature and embedded certificates."""

    name = "signature"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze PE signature presence and embedded certificates."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            sample_data = resolved_path.read_bytes()
            pe = pefile.PE(
                str(resolved_path),
                fast_load=False,
            )

            try:
                security_offset, security_size = _security_directory(pe)
            finally:
                pe.close()

            signature_present = bool(security_offset and security_size)

            pkcs7_blob = _extract_pkcs7_blob(
                sample_data,
                security_offset,
                security_size,
            )

            parsed_certificates: tuple[x509.Certificate, ...] = ()

            if pkcs7_blob is not None:
                parsed_certificates = _load_certificates(pkcs7_blob)

            now = datetime.now(UTC)

            certificates = tuple(
                _certificate_info(certificate, now) for certificate in parsed_certificates
            )

            status = _status_from_certificates(
                signature_present=signature_present,
                certificates=certificates,
            )

            analysis_data = SignatureAnalysisData(
                status=status,
                is_signed=signature_present,
                signature_present=signature_present,
                signature_valid=None,
                trust_verified=None,
                signer_count=len(certificates),
                certificates=certificates,
                digest_algorithm=(
                    _digest_algorithm(pkcs7_blob) if pkcs7_blob is not None else None
                ),
                timestamp_present=False,
                timestamp=None,
                verification_error=(
                    None
                    if pkcs7_blob is not None or not signature_present
                    else "Security directory exists but PKCS#7 data could not be parsed."
                ),
            )

            findings = _build_findings(analysis_data)
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.COMPLETED,
                started_at=started_at,
                duration_ms=duration_ms,
                findings=findings,
                data=analysis_data.model_dump(mode="json"),
            )

        except pefile.PEFormatError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.FAILED,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=False,
                    ),
                ),
            )

        except ValueError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.PARTIAL,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )

        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.PARTIAL,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
