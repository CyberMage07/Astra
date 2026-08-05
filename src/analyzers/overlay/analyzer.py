"""PE overlay analysis for Astra."""

from __future__ import annotations

import hashlib
import math
import time
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    OverlayAnalysisData,
    Severity,
)

HIGH_ENTROPY_THRESHOLD = 7.2
LARGE_OVERLAY_THRESHOLD = 5 * 1024 * 1024
LARGE_OVERLAY_PERCENTAGE = 25.0
WIN_CERTIFICATE_HEADER_SIZE = 8
WIN_CERTIFICATE_REVISION_2_0 = 0x0200
WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA = 0x0002

NSIS_MARKERS = (
    b"NullsoftInst",
    b"Nullsoft Install System",
)


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for overlay content."""
    if not data:
        return 0.0

    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    data_length = len(data)
    entropy = 0.0

    for count in frequencies:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def _detect_embedded_file_type(
    data: bytes,
) -> tuple[
    str | None,
    bool,
    bool,
    bool,
    bool,
]:
    """Detect common file signatures at the beginning of an overlay."""
    if data.startswith(b"MZ"):
        return "pe", True, False, False, False

    if data.startswith(b"\x7fELF"):
        return "elf", True, False, False, False

    if data.startswith(b"PK\x03\x04"):
        return "zip", False, True, False, False

    if data.startswith(b"%PDF-"):
        return "pdf", False, False, True, False

    if data.startswith(b"{\\rtf"):
        return "rtf", False, False, True, False

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", False, False, False, False

    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", False, False, False, False

    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif", False, False, False, False

    if data.startswith(b"BM"):
        return "bitmap", False, False, False, False

    stripped = data.lstrip()

    if stripped.startswith(b"#!"):
        return "script", False, False, False, True

    if stripped.startswith(b"<html") or stripped.startswith(b"<!DOCTYPE html"):
        return "html", False, False, True, False

    return None, False, False, False, False


def _overlay_offset(
    pe: pefile.PE,
) -> int | None:
    """Return the overlay file offset if one exists."""
    offset = pe.get_overlay_data_start_offset()

    if offset is None:
        return None

    return int(offset)


def _is_certificate_table(
    data: bytes,
) -> bool:
    """Return whether data begins with a complete WIN_CERTIFICATE structure."""
    if len(data) < WIN_CERTIFICATE_HEADER_SIZE:
        return False

    certificate_length = int.from_bytes(
        data[0:4],
        byteorder="little",
    )
    revision = int.from_bytes(
        data[4:6],
        byteorder="little",
    )
    certificate_type = int.from_bytes(
        data[6:8],
        byteorder="little",
    )

    return (
        certificate_length >= WIN_CERTIFICATE_HEADER_SIZE
        and certificate_length <= len(data)
        and revision == WIN_CERTIFICATE_REVISION_2_0
        and certificate_type == WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA
    )


def _detect_installer_payload(
    data: bytes,
) -> str | None:
    """Detect recognized installer payload markers."""
    prefix = data[:4096]

    if any(marker in prefix for marker in NSIS_MARKERS):
        return "nsis"

    return None


def _build_findings(
    data: OverlayAnalysisData,
) -> tuple[Finding, ...]:
    """Create calibrated findings from overlay properties."""
    findings: list[Finding] = []

    if not data.overlay_present:
        return ()
    if data.is_certificate_table:
        return ()
    if data.is_installer_payload:
        return ()

    if data.is_executable:
        findings.append(
            Finding(
                title="Executable payload detected in PE overlay",
                description=("The PE overlay begins with an embedded executable file signature."),
                category="pe-overlay-payload",
                severity=Severity.HIGH,
                confidence=90,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=data.embedded_file_type or "executable",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "size": data.size,
                            "entropy": data.entropy,
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "embedded-payload",
                ),
                attack_techniques=("T1027.009",),
            )
        )

    if data.is_archive:
        findings.append(
            Finding(
                title="Archive payload detected in PE overlay",
                description=("The PE overlay begins with an embedded archive file signature."),
                category="pe-overlay-payload",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=data.embedded_file_type or "archive",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "size": data.size,
                            "entropy": data.entropy,
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "archive",
                ),
                attack_techniques=("T1027.009",),
            )
        )

    if data.is_script:
        findings.append(
            Finding(
                title="Script content detected in PE overlay",
                description=("The PE overlay begins with script-like content."),
                category="pe-overlay-payload",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=data.embedded_file_type or "script",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "size": data.size,
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "script",
                ),
            )
        )

    if data.is_document:
        findings.append(
            Finding(
                title="Document content detected in PE overlay",
                description=("The PE overlay begins with an embedded document file signature."),
                category="pe-overlay-payload",
                severity=Severity.LOW,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=data.embedded_file_type or "document",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "size": data.size,
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "document",
                ),
            )
        )

    if data.is_high_entropy and not data.is_executable and not data.is_archive:
        findings.append(
            Finding(
                title="High-entropy PE overlay detected",
                description=(
                    "The PE contains a high-entropy overlay that may "
                    "hold compressed or encrypted content."
                ),
                category="pe-overlay-entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=f"{data.entropy:.2f}",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "size": data.size,
                            "percentage_of_file": (data.percentage_of_file),
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "entropy",
                    "packing",
                ),
                attack_techniques=("T1027",),
            )
        )

    if data.is_large and not data.is_executable and not data.is_archive:
        findings.append(
            Finding(
                title="Large PE overlay detected",
                description=("A significant amount of data exists after the mapped PE image."),
                category="pe-overlay-size",
                severity=Severity.LOW,
                confidence=65,
                evidence=(
                    Evidence(
                        kind="pe-overlay",
                        value=f"{data.size} bytes",
                        location=(
                            f"File offset 0x{data.offset:x}"
                            if data.offset is not None
                            else "PE overlay"
                        ),
                        metadata={
                            "percentage_of_file": (data.percentage_of_file),
                            "sha256": data.sha256,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "overlay",
                    "size",
                ),
            )
        )

    return tuple(findings)


class OverlayAnalyzer:
    """Analyze data appended after the mapped PE image."""

    name = "overlay"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze PE overlay content."""
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
                offset = _overlay_offset(pe)
            finally:
                pe.close()

            if offset is None or offset >= len(sample_data):
                analysis_data = OverlayAnalysisData(
                    overlay_present=False,
                )
            else:
                overlay_data = sample_data[offset:]
                size = len(overlay_data)

                is_certificate_table = _is_certificate_table(overlay_data)

                installer_type = _detect_installer_payload(overlay_data)
                is_installer_payload = installer_type is not None

                percentage_of_file = size / len(sample_data) * 100 if sample_data else 0.0

                entropy = _calculate_entropy(overlay_data)

                (
                    embedded_file_type,
                    is_executable,
                    is_archive,
                    is_document,
                    is_script,
                ) = _detect_embedded_file_type(overlay_data)

                is_high_entropy = entropy >= HIGH_ENTROPY_THRESHOLD
                is_large = (
                    size >= LARGE_OVERLAY_THRESHOLD
                    or percentage_of_file >= LARGE_OVERLAY_PERCENTAGE
                )

                analysis_data = OverlayAnalysisData(
                    overlay_present=True,
                    offset=offset,
                    size=size,
                    percentage_of_file=percentage_of_file,
                    entropy=entropy,
                    sha256=hashlib.sha256(overlay_data).hexdigest(),
                    embedded_file_type=embedded_file_type,
                    is_executable=is_executable,
                    is_archive=is_archive,
                    is_document=is_document,
                    is_script=is_script,
                    is_certificate_table=(is_certificate_table),
                    is_installer_payload=(is_installer_payload),
                    installer_type=installer_type,
                    is_high_entropy=is_high_entropy,
                    is_large=is_large,
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
