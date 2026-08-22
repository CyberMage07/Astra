"""ELF section entropy and layout anomaly analysis for Astra."""

from __future__ import annotations

import math
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFSectionAnalysisData,
    ELFSectionEntry,
    Evidence,
    Finding,
    Severity,
)

HIGH_ENTROPY_THRESHOLD = 7.20
UNUSUALLY_LARGE_SECTION_TABLE_THRESHOLD = 128

SUSPICIOUS_SECTION_NAMES = {
    ".upx",
    ".upx0",
    ".upx1",
    ".packed",
    ".packer",
    ".crypt",
    ".encrypted",
    ".stub",
    ".payload",
    ".shellcode",
}


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _entropy(
    data: bytes,
) -> float:
    """Calculate Shannon entropy for one byte sequence."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _safe_int(
    value: object,
) -> int:
    """Normalize an ELF integer field."""
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    return 0


def _is_suspicious_name(
    name: str,
) -> bool:
    """Return whether a section name looks packing-related."""
    normalized = name.strip().casefold()

    if normalized in SUSPICIOUS_SECTION_NAMES:
        return True

    suspicious_fragments = (
        "upx",
        "pack",
        "crypt",
        "enc",
        "payload",
        "shell",
    )

    return any(fragment in normalized for fragment in suspicious_fragments)


def _section_data(
    section: object,
) -> bytes:
    """Read section contents safely."""
    data_method = getattr(
        section,
        "data",
        None,
    )

    if not callable(data_method):
        return b""

    try:
        data = data_method()
    except Exception:
        return b""

    if isinstance(
        data,
        bytes,
    ):
        return data

    return b""


def _normalize_section(
    *,
    index: int,
    section: object,
    file_size: int,
) -> ELFSectionEntry:
    """Normalize one ELF section."""
    name = str(
        getattr(
            section,
            "name",
            "",
        )
        or "(unnamed)"
    )

    header = getattr(
        section,
        "header",
        {},
    )

    section_type = str(
        header.get(
            "sh_type",
            "unknown",
        )
    )

    address = _safe_int(
        header.get(
            "sh_addr",
            0,
        )
    )

    offset = _safe_int(
        header.get(
            "sh_offset",
            0,
        )
    )

    size = _safe_int(
        header.get(
            "sh_size",
            0,
        )
    )

    flags = _safe_int(
        header.get(
            "sh_flags",
            0,
        )
    )

    alignment = _safe_int(
        header.get(
            "sh_addralign",
            0,
        )
    )

    allocatable = bool(flags & SH_FLAGS.SHF_ALLOC)

    executable = bool(flags & SH_FLAGS.SHF_EXECINSTR)

    writable = bool(flags & SH_FLAGS.SHF_WRITE)

    rwx = bool(allocatable and executable and writable)

    data = _section_data(section)

    entropy = _entropy(data)

    high_entropy = bool(size > 0 and entropy >= HIGH_ENTROPY_THRESHOLD)

    zero_sized_mapped = bool(size == 0 and allocatable and address != 0)

    file_backed = section_type != "SHT_NOBITS"
    out_of_bounds = bool(
        file_backed and size > 0 and (offset > file_size or offset + size > file_size)
    )

    malformed = bool(offset < 0 or size < 0 or address < 0 or alignment < 0)

    return ELFSectionEntry(
        index=index,
        name=name,
        section_type=section_type,
        address=address,
        offset=offset,
        size=size,
        flags=flags,
        alignment=alignment,
        entropy=entropy,
        allocatable=allocatable,
        executable=executable,
        writable=writable,
        rwx=rwx,
        high_entropy=high_entropy,
        suspicious_name=(_is_suspicious_name(name)),
        zero_sized_mapped=(zero_sized_mapped),
        overlapping=False,
        out_of_bounds=(out_of_bounds),
        malformed=malformed,
    )


def _mark_overlaps(
    sections: tuple[ELFSectionEntry, ...],
) -> tuple[ELFSectionEntry, ...]:
    """Mark sections whose file-backed ranges overlap."""
    overlapping_indexes: set[int] = set()

    candidates = [section for section in sections if section.size > 0 and not section.out_of_bounds]
    candidates = [
        section
        for section in sections
        if (section.size > 0 and section.section_type != "SHT_NOBITS" and not section.out_of_bounds)
    ]

    for index, first in enumerate(candidates):
        first_start = first.offset
        first_end = first.offset + first.size

        for second in candidates[index + 1 :]:
            second_start = second.offset
            second_end = second.offset + second.size

            if first_start < second_end and second_start < first_end:
                overlapping_indexes.add(first.index)
                overlapping_indexes.add(second.index)

    return tuple(
        section.model_copy(update={"overlapping": (section.index in overlapping_indexes)})
        for section in sections
    )


def _extract_sections(
    elf: ELFFile,
    *,
    file_size: int,
) -> tuple[
    tuple[ELFSectionEntry, ...],
    int,
]:
    """Extract normalized ELF sections."""
    sections: list[ELFSectionEntry] = []

    malformed_count = 0

    for index, section in enumerate(elf.iter_sections()):
        try:
            normalized = _normalize_section(
                index=index,
                section=section,
                file_size=file_size,
            )

            if normalized.malformed:
                malformed_count += 1

            sections.append(normalized)

        except Exception:
            malformed_count += 1

    return (
        _mark_overlaps(tuple(sections)),
        malformed_count,
    )


def _build_data(
    elf: ELFFile,
    *,
    file_size: int,
) -> ELFSectionAnalysisData:
    """Build complete ELF section-analysis data."""
    (
        sections,
        malformed_count,
    ) = _extract_sections(
        elf,
        file_size=file_size,
    )

    entropies = [section.entropy for section in sections if section.size > 0]

    average_entropy = sum(entropies) / len(entropies) if entropies else 0.0

    maximum_entropy = max(entropies) if entropies else 0.0

    return ELFSectionAnalysisData(
        section_count=len(sections),
        executable_section_count=sum(section.executable for section in sections),
        writable_section_count=sum(section.writable for section in sections),
        rwx_section_count=sum(section.rwx for section in sections),
        high_entropy_section_count=sum(section.high_entropy for section in sections),
        suspicious_name_count=sum(section.suspicious_name for section in sections),
        zero_sized_mapped_count=sum(section.zero_sized_mapped for section in sections),
        overlapping_section_count=sum(section.overlapping for section in sections),
        out_of_bounds_section_count=sum(section.out_of_bounds for section in sections),
        malformed_section_count=(malformed_count),
        unusually_large_section_table=(len(sections) >= UNUSUALLY_LARGE_SECTION_TABLE_THRESHOLD),
        average_entropy=(average_entropy),
        maximum_entropy=(maximum_entropy),
        sections=sections,
    )


def _build_findings(
    data: ELFSectionAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative ELF section findings."""
    findings: list[Finding] = []

    rwx_sections = tuple(section for section in data.sections if section.rwx)

    if rwx_sections:
        findings.append(
            Finding(
                title=("Writable and executable ELF sections detected"),
                description=(
                    "One or more ELF sections are both writable "
                    "and executable. RWX memory regions can reduce "
                    "exploit mitigations and are also seen in some "
                    "packed or self-modifying binaries."
                ),
                category="elf-section-permissions",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="elf-section",
                        value=section.name,
                        location=(f"section[{section.index}]"),
                    )
                    for section in rwx_sections[:20]
                ),
                tags=(
                    "elf",
                    "sections",
                    "rwx",
                ),
            )
        )

    high_entropy_executable = tuple(
        section for section in data.sections if (section.executable and section.high_entropy)
    )

    if high_entropy_executable:
        findings.append(
            Finding(
                title=("High-entropy executable ELF sections detected"),
                description=(
                    "Executable sections with unusually high entropy "
                    "were detected. This can be associated with "
                    "compression, encryption, packing, or heavily "
                    "optimized code and should be correlated with "
                    "other evidence."
                ),
                category="elf-section-entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="elf-section",
                        value=section.name,
                        location=(f"section[{section.index}]"),
                        metadata={
                            "entropy": (section.entropy),
                        },
                    )
                    for section in high_entropy_executable[:20]
                ),
                tags=(
                    "elf",
                    "sections",
                    "entropy",
                ),
            )
        )

    suspicious_names = tuple(section for section in data.sections if section.suspicious_name)

    if suspicious_names:
        findings.append(
            Finding(
                title=("Suspicious ELF section names detected"),
                description=(
                    "One or more ELF section names resemble names "
                    "commonly associated with packed, encrypted, "
                    "or embedded payload content."
                ),
                category="elf-section-name",
                severity=Severity.LOW,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="elf-section",
                        value=section.name,
                        location=(f"section[{section.index}]"),
                    )
                    for section in suspicious_names[:20]
                ),
                tags=(
                    "elf",
                    "sections",
                    "packing",
                ),
            )
        )

    malformed_sections = tuple(
        section
        for section in data.sections
        if (section.malformed or section.out_of_bounds or section.overlapping)
    )

    if malformed_sections:
        findings.append(
            Finding(
                title=("Abnormal ELF section layout detected"),
                description=(
                    "One or more ELF sections contain malformed, "
                    "overlapping, or out-of-bounds file layout "
                    "metadata. This may indicate corruption, "
                    "obfuscation, packing, or parser-evasion behavior."
                ),
                category="elf-section-layout",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=tuple(
                    Evidence(
                        kind="elf-section",
                        value=section.name,
                        location=(f"section[{section.index}]"),
                        metadata={
                            "malformed": (section.malformed),
                            "overlapping": (section.overlapping),
                            "out_of_bounds": (section.out_of_bounds),
                        },
                    )
                    for section in malformed_sections[:20]
                ),
                tags=(
                    "elf",
                    "sections",
                    "layout",
                ),
            )
        )

    if data.unusually_large_section_table:
        findings.append(
            Finding(
                title=("Unusually large ELF section table"),
                description=(
                    "The ELF file contains an unusually high number "
                    "of sections. This is not inherently malicious "
                    "but may indicate generated, instrumented, "
                    "obfuscated, or intentionally complex content."
                ),
                category="elf-section-layout",
                severity=Severity.INFO,
                confidence=55,
                evidence=(
                    Evidence(
                        kind="elf-sections",
                        value=str(data.section_count),
                        location="ELF section table",
                    ),
                ),
                tags=(
                    "elf",
                    "sections",
                ),
            )
        )

    return tuple(findings)


class ELFSectionsAnalyzer:
    """Analyze ELF section entropy and layout anomalies."""

    name = "elfsections"
    version = "0.1.0"

    supported_families = frozenset(
        {
            "elf",
        }
    )

    def supports(
        self,
        family: str,
    ) -> bool:
        """Return whether this analyzer supports the family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze ELF sections."""
        started_at = datetime.now(UTC)

        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            file_size = resolved_path.stat().st_size

            with resolved_path.open("rb") as file_object:
                elf = _load_elf(file_object)

                analysis_data = _build_data(
                    elf,
                    file_size=file_size,
                )

            findings = _build_findings(analysis_data)

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.COMPLETED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                findings=findings,
                data=(analysis_data.model_dump(mode="json")),
            )

        except ValueError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.FAILED),
                started_at=(started_at),
                duration_ms=(duration_ms),
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
                analyzer_version=(self.version),
                status=(AnalysisStatus.PARTIAL),
                started_at=(started_at),
                duration_ms=(duration_ms),
                errors=(
                    AnalyzerError(
                        error_type=(type(error).__name__),
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
