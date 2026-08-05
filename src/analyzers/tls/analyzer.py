"""PE TLS callback analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    Severity,
    TLSAnalysisData,
    TLSCallbackEntry,
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MAX_CALLBACKS = 64
SUSPICIOUS_CALLBACK_THRESHOLD = 8


def _decode_section_name(
    section: Any,
) -> str:
    """Return a normalized PE section name."""
    raw_name = getattr(section, "Name", b"")

    if isinstance(raw_name, bytes):
        return raw_name.rstrip(b"\x00").decode(
            "utf-8",
            errors="replace",
        )

    return str(raw_name)


def _image_bounds(
    pe: pefile.PE,
) -> tuple[int, int]:
    """Return the loaded image start and end virtual addresses."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

    return image_base, image_base + size_of_image


def _section_for_rva(
    pe: pefile.PE,
    relative_virtual_address: int,
) -> Any | None:
    """Return the section containing an RVA."""
    for section in pe.sections:
        section_start = int(section.VirtualAddress)
        section_size = max(
            int(section.Misc_VirtualSize),
            int(section.SizeOfRawData),
        )
        section_end = section_start + section_size

        if section_start <= relative_virtual_address < section_end:
            return section

    return None


def _callback_entry(
    pe: pefile.PE,
    *,
    index: int,
    virtual_address: int,
) -> TLSCallbackEntry:
    """Normalize one TLS callback address."""
    image_base, image_end = _image_bounds(pe)

    is_outside_image = not (image_base <= virtual_address < image_end)

    relative_virtual_address: int | None = None
    file_offset: int | None = None
    section_name: str | None = None
    is_mapped = False
    is_executable = False
    is_writable = False

    if not is_outside_image:
        relative_virtual_address = virtual_address - image_base

        section = _section_for_rva(
            pe,
            relative_virtual_address,
        )

        if section is not None:
            is_mapped = True
            section_name = _decode_section_name(section)

            characteristics = int(section.Characteristics)
            is_executable = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
            is_writable = bool(characteristics & IMAGE_SCN_MEM_WRITE)

            try:
                file_offset = int(pe.get_offset_from_rva(relative_virtual_address))
            except (pefile.PEFormatError, ValueError):
                file_offset = None

    return TLSCallbackEntry(
        index=index,
        virtual_address=virtual_address,
        relative_virtual_address=(relative_virtual_address),
        file_offset=file_offset,
        section_name=section_name,
        is_mapped=is_mapped,
        is_executable=is_executable,
        is_writable=is_writable,
        is_outside_image=is_outside_image,
    )


def _read_callback_addresses(
    pe: pefile.PE,
    address_of_callbacks: int,
) -> tuple[int, ...]:
    """Read TLS callback virtual addresses from the callback table."""
    if address_of_callbacks <= 0:
        return ()

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    table_rva = address_of_callbacks - image_base

    if table_rva < 0:
        return ()

    pointer_size = 8 if int(pe.OPTIONAL_HEADER.Magic) == 0x20B else 4

    image = pe.get_memory_mapped_image()
    callbacks: list[int] = []

    for index in range(MAX_CALLBACKS):
        start = table_rva + index * pointer_size
        end = start + pointer_size

        if start < 0 or end > len(image):
            break

        virtual_address = int.from_bytes(
            image[start:end],
            byteorder="little",
        )

        if virtual_address == 0:
            break

        callbacks.append(virtual_address)

    return tuple(callbacks)


def _build_findings(
    data: TLSAnalysisData,
) -> tuple[Finding, ...]:
    """Generate findings from TLS callback properties."""
    findings: list[Finding] = []

    if not data.tls_present:
        return ()

    if data.callback_count > 0:
        findings.append(
            Finding(
                title="TLS callbacks present",
                description=(
                    "The PE defines one or more TLS callbacks "
                    "that execute before the normal entry point."
                ),
                category="execution-flow",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="tls-callback",
                        value=(f"0x{callback.virtual_address:x}"),
                        location=(callback.section_name or "unmapped"),
                        metadata={
                            "index": callback.index,
                            "rva": (callback.relative_virtual_address),
                            "file_offset": callback.file_offset,
                            "is_executable": (callback.is_executable),
                            "is_writable": (callback.is_writable),
                            "is_outside_image": (callback.is_outside_image),
                        },
                    )
                    for callback in data.callbacks[:16]
                ),
                tags=(
                    "pe",
                    "tls",
                    "execution-flow",
                ),
                attack_techniques=("T1622",),
            )
        )

    suspicious_callbacks = tuple(
        callback
        for callback in data.callbacks
        if (
            callback.is_outside_image
            or not callback.is_mapped
            or not callback.is_executable
            or callback.is_writable
        )
    )

    if suspicious_callbacks:
        findings.append(
            Finding(
                title="Suspicious TLS callback locations detected",
                description=(
                    "One or more TLS callbacks point outside "
                    "normal executable sections or into writable "
                    "or unmapped memory."
                ),
                category="anti-analysis",
                severity=Severity.HIGH,
                confidence=85,
                evidence=tuple(
                    Evidence(
                        kind="tls-callback",
                        value=(f"0x{callback.virtual_address:x}"),
                        location=(callback.section_name or "unmapped"),
                        metadata={
                            "mapped": callback.is_mapped,
                            "executable": (callback.is_executable),
                            "writable": (callback.is_writable),
                            "outside_image": (callback.is_outside_image),
                        },
                    )
                    for callback in suspicious_callbacks[:16]
                ),
                tags=(
                    "pe",
                    "tls",
                    "anti-analysis",
                ),
                attack_techniques=("T1622",),
            )
        )

    if data.callback_count >= SUSPICIOUS_CALLBACK_THRESHOLD:
        findings.append(
            Finding(
                title="Unusually large TLS callback table detected",
                description=("The PE contains an unusually high number of TLS callbacks."),
                category="execution-flow",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="tls-callback-count",
                        value=str(data.callback_count),
                        location="PE TLS directory",
                    ),
                ),
                tags=(
                    "pe",
                    "tls",
                    "callback-table",
                ),
                attack_techniques=("T1622",),
            )
        )

    return tuple(findings)


class TLSAnalyzer:
    """Analyze PE TLS directories and callback tables."""

    name = "tls"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze a PE TLS directory and callback table."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            pe = pefile.PE(
                str(resolved_path),
                fast_load=False,
            )

            try:
                if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                    analysis_data = TLSAnalysisData(
                        tls_present=False,
                    )
                else:
                    tls_directory = pe.DIRECTORY_ENTRY_TLS.struct

                    raw_data_start = int(tls_directory.StartAddressOfRawData)
                    raw_data_end = int(tls_directory.EndAddressOfRawData)
                    address_of_index = int(tls_directory.AddressOfIndex)
                    address_of_callbacks = int(tls_directory.AddressOfCallBacks)
                    size_of_zero_fill = int(tls_directory.SizeOfZeroFill)
                    characteristics = int(tls_directory.Characteristics)

                    callback_addresses = _read_callback_addresses(
                        pe,
                        address_of_callbacks,
                    )

                    callbacks = tuple(
                        _callback_entry(
                            pe,
                            index=index,
                            virtual_address=virtual_address,
                        )
                        for index, virtual_address in enumerate(callback_addresses)
                    )

                    mapped_callbacks = sum(callback.is_mapped for callback in callbacks)
                    executable_callbacks = sum(callback.is_executable for callback in callbacks)
                    writable_callbacks = sum(callback.is_writable for callback in callbacks)
                    outside_image_callbacks = sum(
                        callback.is_outside_image for callback in callbacks
                    )
                    suspicious_callbacks = sum(
                        (
                            callback.is_outside_image
                            or not callback.is_mapped
                            or not callback.is_executable
                            or callback.is_writable
                        )
                        for callback in callbacks
                    )

                    analysis_data = TLSAnalysisData(
                        tls_present=True,
                        callback_count=len(callbacks),
                        callbacks=callbacks,
                        raw_data_start=raw_data_start,
                        raw_data_end=raw_data_end,
                        address_of_index=address_of_index,
                        address_of_callbacks=(address_of_callbacks),
                        size_of_zero_fill=size_of_zero_fill,
                        characteristics=characteristics,
                        mapped_callbacks=mapped_callbacks,
                        executable_callbacks=(executable_callbacks),
                        writable_callbacks=(writable_callbacks),
                        outside_image_callbacks=(outside_image_callbacks),
                        suspicious_callbacks=(suspicious_callbacks),
                    )
            finally:
                pe.close()

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
