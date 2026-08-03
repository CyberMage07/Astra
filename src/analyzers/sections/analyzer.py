"""PE section analysis for Astra."""

from __future__ import annotations

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
    SectionAnalysisData,
    SectionInfo,
    Severity,
)

HIGH_ENTROPY_THRESHOLD = 7.2
VIRTUAL_RAW_RATIO_THRESHOLD = 4.0

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

SUSPICIOUS_SECTION_NAMES = {
    ".aspack",
    ".adata",
    ".boom",
    ".ccg",
    ".charmve",
    ".enigma1",
    ".enigma2",
    ".fsg",
    ".mpress1",
    ".mpress2",
    ".packed",
    ".petite",
    ".rsrc1",
    ".themida",
    ".upx0",
    ".upx1",
    ".upx2",
    "aspack",
    "mpress1",
    "mpress2",
    "petite",
    "themida",
    "upx0",
    "upx1",
    "upx2",
}

RESOURCE_SECTION_NAMES = {
    ".rsrc",
    "rsrc",
}


def _decode_section_name(raw_name: bytes) -> str:
    """Decode and normalize a PE section name."""
    return raw_name.rstrip(b"\x00").decode(
        "utf-8",
        errors="replace",
    )


def _section_permissions(
    characteristics: int,
) -> tuple[bool, bool, bool]:
    """Return readable, writable, and executable flags."""
    readable = bool(characteristics & IMAGE_SCN_MEM_READ)
    writable = bool(characteristics & IMAGE_SCN_MEM_WRITE)
    executable = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)

    return readable, writable, executable


def _virtual_raw_anomaly(
    virtual_size: int,
    raw_size: int,
) -> bool:
    """Return whether section virtual and raw sizes are unusual."""
    if virtual_size <= 0:
        return False

    if raw_size == 0:
        return True

    ratio = virtual_size / raw_size

    return ratio >= VIRTUAL_RAW_RATIO_THRESHOLD


def _normalize_section(
    section: pefile.SectionStructure,
) -> SectionInfo:
    """Normalize one PE section."""
    name = _decode_section_name(section.Name)
    normalized_name = name.lower()

    virtual_size = int(section.Misc_VirtualSize)
    raw_size = int(section.SizeOfRawData)
    characteristics = int(section.Characteristics)

    readable, writable, executable = _section_permissions(characteristics)

    is_empty = virtual_size == 0 and raw_size == 0

    is_rwx = readable and writable and executable

    is_wx = writable and executable

    is_suspicious_name = normalized_name in SUSPICIOUS_SECTION_NAMES

    is_executable_resource = normalized_name in RESOURCE_SECTION_NAMES and executable

    return SectionInfo(
        name=name,
        virtual_address=int(section.VirtualAddress),
        virtual_size=virtual_size,
        raw_offset=int(section.PointerToRawData),
        raw_size=raw_size,
        entropy=float(section.get_entropy()),
        characteristics=characteristics,
        readable=readable,
        writable=writable,
        executable=executable,
        is_rwx=is_rwx,
        is_wx=is_wx,
        is_empty=is_empty,
        has_virtual_raw_anomaly=(
            _virtual_raw_anomaly(
                virtual_size,
                raw_size,
            )
        ),
        is_suspicious_name=is_suspicious_name,
        is_executable_resource=(is_executable_resource),
    )


def _build_findings(
    sections: tuple[SectionInfo, ...],
) -> tuple[Finding, ...]:
    """Create security findings from section properties."""
    findings: list[Finding] = []

    high_entropy = tuple(
        section for section in sections if section.entropy >= HIGH_ENTROPY_THRESHOLD
    )

    if high_entropy:
        findings.append(
            Finding(
                title=("High-entropy PE sections detected"),
                description=(
                    f"{len(high_entropy)} PE sections have "
                    f"entropy at or above "
                    f"{HIGH_ENTROPY_THRESHOLD:.1f}, which may "
                    "indicate compression, packing, or "
                    "encrypted content."
                ),
                category="pe-section-entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                        metadata={
                            "entropy": section.entropy,
                            "raw_size": section.raw_size,
                            "virtual_size": (section.virtual_size),
                        },
                    )
                    for section in high_entropy[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "entropy",
                    "packing",
                ),
                attack_techniques=("T1027",),
            )
        )

    rwx_sections = tuple(section for section in sections if section.is_rwx)

    if rwx_sections:
        findings.append(
            Finding(
                title="RWX PE sections detected",
                description=(
                    f"{len(rwx_sections)} PE sections are "
                    "simultaneously readable, writable, and "
                    "executable."
                ),
                category="pe-section-permissions",
                severity=Severity.HIGH,
                confidence=90,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                    )
                    for section in rwx_sections[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "rwx",
                ),
                attack_techniques=("T1027",),
            )
        )

    suspicious_names = tuple(section for section in sections if section.is_suspicious_name)

    if suspicious_names:
        findings.append(
            Finding(
                title=("Suspicious PE section names detected"),
                description=(
                    f"{len(suspicious_names)} PE sections "
                    "match names commonly associated with "
                    "packers or protectors."
                ),
                category="pe-section-name",
                severity=Severity.MEDIUM,
                confidence=85,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                    )
                    for section in suspicious_names[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "packer",
                ),
                attack_techniques=("T1027",),
            )
        )

    executable_resources = tuple(section for section in sections if section.is_executable_resource)

    if executable_resources:
        findings.append(
            Finding(
                title=("Executable resource section detected"),
                description=(
                    "One or more resource sections are marked "
                    "executable, which is unusual for standard "
                    "PE files."
                ),
                category="pe-section-permissions",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                    )
                    for section in executable_resources[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "resource",
                    "executable",
                ),
            )
        )

    empty_executable = tuple(
        section
        for section in sections
        if (section.executable and section.raw_size == 0 and section.virtual_size > 0)
    )

    if empty_executable:
        findings.append(
            Finding(
                title=("Empty executable PE sections detected"),
                description=(
                    f"{len(empty_executable)} executable "
                    "sections have virtual content but no raw "
                    "data."
                ),
                category="pe-section-layout",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                    )
                    for section in empty_executable[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "layout",
                ),
            )
        )

    size_anomalies = tuple(
        section
        for section in sections
        if (
            section.has_virtual_raw_anomaly
            and (
                section.executable
                or section.is_suspicious_name
                or section.entropy >= HIGH_ENTROPY_THRESHOLD
            )
        )
    )

    if size_anomalies:
        findings.append(
            Finding(
                title=("PE section size anomalies detected"),
                description=(
                    f"{len(size_anomalies)} PE sections have "
                    "large differences between virtual and raw "
                    "sizes combined with executable, packed, "
                    "or high-entropy characteristics."
                ),
                category="pe-section-layout",
                severity=Severity.LOW,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="pe-section",
                        value=section.name,
                        location=(f"RVA 0x{section.virtual_address:x}"),
                        metadata={
                            "raw_size": section.raw_size,
                            "virtual_size": (section.virtual_size),
                            "entropy": section.entropy,
                            "executable": (section.executable),
                            "suspicious_name": (section.is_suspicious_name),
                        },
                    )
                    for section in size_anomalies[:20]
                ),
                tags=(
                    "pe",
                    "section",
                    "layout",
                ),
            )
        )

    return tuple(findings)


class SectionsAnalyzer:
    """Analyze PE section structure and permissions."""

    name = "sections"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze PE sections and return normalized results."""
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
                sections = tuple(_normalize_section(section) for section in pe.sections)
            finally:
                pe.close()

            analysis_data = SectionAnalysisData(
                section_count=len(sections),
                sections=sections,
                high_entropy_sections=sum(
                    1 for section in sections if section.entropy >= HIGH_ENTROPY_THRESHOLD
                ),
                executable_sections=sum(1 for section in sections if section.executable),
                writable_sections=sum(1 for section in sections if section.writable),
                rwx_sections=sum(1 for section in sections if section.is_rwx),
                wx_sections=sum(1 for section in sections if section.is_wx),
                suspicious_name_sections=sum(
                    1 for section in sections if section.is_suspicious_name
                ),
                empty_executable_sections=sum(
                    1
                    for section in sections
                    if (section.executable and section.raw_size == 0 and section.virtual_size > 0)
                ),
                virtual_raw_anomalies=sum(
                    1 for section in sections if section.has_virtual_raw_anomaly
                ),
                executable_resource_sections=sum(
                    1 for section in sections if section.is_executable_resource
                ),
            )

            findings = _build_findings(sections)
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
