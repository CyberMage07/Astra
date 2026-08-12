"""PE export-table analysis for Astra."""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    ExportAnalysisData,
    ExportEntry,
    Finding,
    Severity,
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000

LARGE_EXPORT_TABLE_THRESHOLD = 4096

SUSPICIOUS_EXPORT_NAMES = {
    "runpayload",
    "payload",
    "inject",
    "injectprocess",
    "createremotethread",
    "shellcode",
    "reverse_shell",
    "reverseshell",
    "downloadexecute",
    "downloadandexecute",
    "executecommand",
    "execcommand",
    "keylogger",
    "dumpcredentials",
    "credentialdump",
    "persist",
    "installhook",
}


def _decode_bytes(
    value: bytes | None,
) -> str | None:
    """Decode a PE string safely."""
    if value is None:
        return None

    decoded = value.decode(
        "utf-8",
        errors="replace",
    ).strip()

    return decoded or None


def _section_for_rva(
    pe: pefile.PE,
    rva: int,
) -> object | None:
    """Return the section containing an RVA."""
    for section in pe.sections:
        start = int(section.VirtualAddress)
        virtual_size = int(
            max(
                section.Misc_VirtualSize,
                section.SizeOfRawData,
            )
        )
        end = start + virtual_size

        if start <= rva < end:
            return cast(
                object,
                section,
            )

    return None


def _section_name(
    section: object | None,
) -> str | None:
    """Return a normalized PE section name."""
    if section is None:
        return None

    raw_name = getattr(
        section,
        "Name",
        b"",
    )

    if not isinstance(
        raw_name,
        bytes,
    ):
        return None

    return (
        raw_name.rstrip(b"\x00")
        .decode(
            "utf-8",
            errors="replace",
        )
        .strip()
        or None
    )


def _section_is_executable(
    section: object | None,
) -> bool:
    """Return whether a section is executable."""
    if section is None:
        return False

    characteristics = int(
        getattr(
            section,
            "Characteristics",
            0,
        )
    )

    return bool(characteristics & IMAGE_SCN_MEM_EXECUTE)


def _suspicious_export_name(
    name: str | None,
) -> bool:
    """Return whether an export name appears suspicious."""
    if not name:
        return False

    normalized = name.casefold().replace("-", "").replace("_", "")

    normalized_suspicious = {value.replace("_", "") for value in SUSPICIOUS_EXPORT_NAMES}

    if normalized in normalized_suspicious:
        return True

    suspicious_fragments = (
        "shellcode",
        "inject",
        "keylog",
        "credential",
        "dumpcred",
        "reverse",
        "payload",
    )

    return any(fragment in normalized for fragment in suspicious_fragments)


def _normalize_export(
    pe: pefile.PE,
    symbol: object,
) -> ExportEntry:
    """Normalize one exported symbol."""
    ordinal = int(
        getattr(
            symbol,
            "ordinal",
            0,
        )
    )
    rva = int(
        getattr(
            symbol,
            "address",
            0,
        )
    )

    name_value = getattr(
        symbol,
        "name",
        None,
    )
    name = (
        _decode_bytes(name_value)
        if isinstance(
            name_value,
            bytes,
        )
        else (str(name_value) if name_value is not None else None)
    )

    forwarder_value = getattr(
        symbol,
        "forwarder",
        None,
    )
    forwarder = (
        _decode_bytes(forwarder_value)
        if isinstance(
            forwarder_value,
            bytes,
        )
        else (str(forwarder_value) if forwarder_value is not None else None)
    )

    section = _section_for_rva(
        pe,
        rva,
    )

    is_forwarded = forwarder is not None
    is_mapped = section is not None or is_forwarded
    is_executable = _section_is_executable(section) if not is_forwarded else False

    malformed = ordinal <= 0 or (not is_forwarded and not is_mapped)

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)

    return ExportEntry(
        ordinal=ordinal,
        name=name,
        address=image_base + rva,
        rva=rva,
        forwarder=forwarder,
        is_forwarded=is_forwarded,
        section_name=_section_name(section),
        is_mapped=is_mapped,
        is_executable=is_executable,
        suspicious_name=(_suspicious_export_name(name)),
        malformed=malformed,
    )


def _extract_export_data(
    pe: pefile.PE,
) -> ExportAnalysisData:
    """Extract normalized PE export-table data."""
    directory = getattr(
        pe,
        "DIRECTORY_ENTRY_EXPORT",
        None,
    )

    if directory is None:
        return ExportAnalysisData(
            export_directory_present=False,
        )

    structure = getattr(
        directory,
        "struct",
        None,
    )

    module_name = _decode_bytes(
        getattr(
            directory,
            "name",
            None,
        )
    )

    symbols = tuple(
        getattr(
            directory,
            "symbols",
            (),
        )
    )

    exports = tuple(
        _normalize_export(
            pe,
            symbol,
        )
        for symbol in symbols
    )

    names = tuple(entry.name.casefold() for entry in exports if entry.name)
    ordinals = tuple(entry.ordinal for entry in exports)

    name_counts = Counter(names)
    ordinal_counts = Counter(ordinals)

    duplicate_name_count = sum(count - 1 for count in name_counts.values() if count > 1)
    duplicate_ordinal_count = sum(count - 1 for count in ordinal_counts.values() if count > 1)

    malformed_export_count = sum(entry.malformed for entry in exports)

    if structure is None:
        malformed_export_count = max(
            1,
            malformed_export_count,
        )

    return ExportAnalysisData(
        export_directory_present=True,
        module_name=module_name,
        export_count=len(exports),
        named_export_count=sum(entry.name is not None for entry in exports),
        ordinal_only_count=sum(entry.name is None for entry in exports),
        forwarded_export_count=sum(entry.is_forwarded for entry in exports),
        executable_export_count=sum(entry.is_executable for entry in exports),
        unmapped_export_count=sum(
            not entry.is_mapped and not entry.is_forwarded for entry in exports
        ),
        suspicious_name_count=sum(entry.suspicious_name for entry in exports),
        malformed_export_count=(malformed_export_count),
        duplicate_name_count=(duplicate_name_count),
        duplicate_ordinal_count=(duplicate_ordinal_count),
        unusually_large_export_table=(len(exports) > LARGE_EXPORT_TABLE_THRESHOLD),
        exports=exports,
    )


def _build_findings(
    data: ExportAnalysisData,
) -> tuple[Finding, ...]:
    """Generate calibrated findings from PE exports."""
    findings: list[Finding] = []

    if not data.export_directory_present:
        return ()

    suspicious_exports = tuple(entry for entry in data.exports if entry.suspicious_name)

    if suspicious_exports:
        findings.append(
            Finding(
                title=("Suspicious PE export names detected"),
                description=(
                    "One or more exported function names "
                    "contain terminology commonly associated "
                    "with payload execution, injection, "
                    "credential access, or similar offensive "
                    "capabilities."
                ),
                category="pe-exports",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="export",
                        value=(entry.name or f"ordinal:{entry.ordinal}"),
                        location=(entry.section_name or "PE export directory"),
                        metadata={
                            "ordinal": entry.ordinal,
                            "rva": entry.rva,
                        },
                    )
                    for entry in suspicious_exports[:20]
                ),
                tags=(
                    "pe",
                    "exports",
                    "suspicious-name",
                ),
            )
        )

    malformed_exports = tuple(entry for entry in data.exports if entry.malformed)

    if data.malformed_export_count:
        findings.append(
            Finding(
                title=("Malformed or unmapped PE exports detected"),
                description=(
                    "One or more export records contain invalid "
                    "ordinals or point outside mapped PE sections."
                ),
                category="pe-exports",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="export",
                        value=(entry.name or f"ordinal:{entry.ordinal}"),
                        location=(entry.section_name or "unmapped"),
                        metadata={
                            "ordinal": entry.ordinal,
                            "rva": entry.rva,
                        },
                    )
                    for entry in malformed_exports[:20]
                ),
                tags=(
                    "pe",
                    "exports",
                    "malformed",
                ),
            )
        )

    if data.duplicate_name_count or data.duplicate_ordinal_count:
        findings.append(
            Finding(
                title=("Duplicate PE export records detected"),
                description=(
                    "The export table contains duplicate names "
                    "or ordinals. This may indicate malformed "
                    "or intentionally unusual export metadata."
                ),
                category="pe-exports",
                severity=Severity.LOW,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="export-table",
                        value="duplicates",
                        location="PE export directory",
                        metadata={
                            "duplicate_names": (data.duplicate_name_count),
                            "duplicate_ordinals": (data.duplicate_ordinal_count),
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "exports",
                    "duplicates",
                ),
            )
        )

    if data.unusually_large_export_table:
        findings.append(
            Finding(
                title=("Unusually large PE export table detected"),
                description=(
                    "The PE contains an unusually large number "
                    "of exported symbols. This is contextual "
                    "metadata and should be correlated with the "
                    "binary type and observed behavior."
                ),
                category="pe-exports",
                severity=Severity.INFO,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="export-count",
                        value=str(data.export_count),
                        location="PE export directory",
                    ),
                ),
                tags=(
                    "pe",
                    "exports",
                    "large-table",
                ),
            )
        )

    return tuple(findings)


class ExportsAnalyzer:
    """Analyze PE export-directory metadata and symbols."""

    name = "exports"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(
        self,
        family: str,
    ) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze the PE export directory."""
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
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                )

                analysis_data = _extract_export_data(pe)
            finally:
                pe.close()

            findings = _build_findings(analysis_data)

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=(AnalysisStatus.COMPLETED),
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
                        error_type=(type(error).__name__),
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
                        error_type=(type(error).__name__),
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
