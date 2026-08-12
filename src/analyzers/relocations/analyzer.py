"""PE base-relocation analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    RelocationAnalysisData,
    RelocationBlock,
    RelocationEntry,
    Severity,
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

LARGE_RELOCATION_TABLE_THRESHOLD = 100_000

RELOCATION_TYPE_NAMES: dict[int, str] = {
    0: "ABSOLUTE",
    1: "HIGH",
    2: "LOW",
    3: "HIGHLOW",
    4: "HIGHADJ",
    5: "MIPS_JMPADDR",
    6: "SECTION",
    7: "REL32",
    9: "MIPS_JMPADDR16",
    10: "DIR64",
}


def _relocation_type_name(
    relocation_type: int,
) -> str:
    """Return a readable PE relocation type."""
    return RELOCATION_TYPE_NAMES.get(
        relocation_type,
        f"UNKNOWN_{relocation_type}",
    )


def _section_for_rva(
    pe: pefile.PE,
    rva: int,
) -> object | None:
    """Return the PE section containing an RVA."""
    for section in pe.sections:
        start = int(section.VirtualAddress)
        size = int(
            max(
                section.Misc_VirtualSize,
                section.SizeOfRawData,
            )
        )
        end = start + size

        if start <= rva < end:
            return cast(
                object,
                section,
            )

    return None


def _section_name(
    section: object | None,
) -> str | None:
    """Return a normalized section name."""
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


def _section_is_writable(
    section: object | None,
) -> bool:
    """Return whether a section is writable."""
    if section is None:
        return False

    characteristics = int(
        getattr(
            section,
            "Characteristics",
            0,
        )
    )

    return bool(characteristics & IMAGE_SCN_MEM_WRITE)


def _image_bounds(
    pe: pefile.PE,
) -> tuple[int, int]:
    """Return the valid loaded-image RVA range."""
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

    return (
        0,
        size_of_image,
    )


def _normalize_entry(
    pe: pefile.PE,
    *,
    block_index: int,
    entry_index: int,
    entry: object,
) -> RelocationEntry:
    """Normalize one PE relocation entry."""
    relocation_type = int(
        getattr(
            entry,
            "type",
            0,
        )
    )
    rva = int(
        getattr(
            entry,
            "rva",
            0,
        )
    )

    section = _section_for_rva(
        pe,
        rva,
    )

    image_start, image_end = _image_bounds(pe)

    is_mapped = section is not None

    malformed = rva < image_start or rva >= image_end or (relocation_type != 0 and not is_mapped)

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)

    return RelocationEntry(
        block_index=block_index,
        entry_index=entry_index,
        relocation_type=relocation_type,
        relocation_type_name=(_relocation_type_name(relocation_type)),
        rva=max(
            0,
            rva,
        ),
        virtual_address=(
            image_base
            + max(
                0,
                rva,
            )
        ),
        section_name=_section_name(section),
        is_mapped=is_mapped,
        is_executable=(_section_is_executable(section)),
        is_writable=(_section_is_writable(section)),
        malformed=malformed,
    )


def _normalize_block(
    pe: pefile.PE,
    *,
    block_index: int,
    block: object,
) -> RelocationBlock:
    """Normalize one PE relocation block."""
    structure = getattr(
        block,
        "struct",
        None,
    )

    page_rva = 0
    block_size = 0

    if structure is not None:
        page_rva = int(
            getattr(
                structure,
                "VirtualAddress",
                0,
            )
        )
        block_size = int(
            getattr(
                structure,
                "SizeOfBlock",
                0,
            )
        )

    raw_entries = tuple(
        getattr(
            block,
            "entries",
            (),
        )
    )

    entries = tuple(
        _normalize_entry(
            pe,
            block_index=block_index,
            entry_index=entry_index,
            entry=entry,
        )
        for entry_index, entry in enumerate(raw_entries)
    )

    malformed_entry_count = sum(entry.malformed for entry in entries)

    if structure is None:
        malformed_entry_count = max(
            1,
            malformed_entry_count,
        )

    return RelocationBlock(
        index=block_index,
        page_rva=max(
            0,
            page_rva,
        ),
        block_size=max(
            0,
            block_size,
        ),
        entry_count=len(entries),
        malformed_entry_count=(malformed_entry_count),
        entries=entries,
    )


def _extract_data(
    pe: pefile.PE,
) -> RelocationAnalysisData:
    """Extract normalized PE base-relocation data."""
    raw_blocks = tuple(
        getattr(
            pe,
            "DIRECTORY_ENTRY_BASERELOC",
            (),
        )
    )

    if not raw_blocks:
        return RelocationAnalysisData(
            relocation_directory_present=False,
        )

    blocks = tuple(
        _normalize_block(
            pe,
            block_index=index,
            block=block,
        )
        for index, block in enumerate(raw_blocks)
    )

    entries = tuple(entry for block in blocks for entry in block.entries)

    relocation_types = tuple(sorted({entry.relocation_type_name for entry in entries}))

    unknown_type_count = sum(
        entry.relocation_type not in RELOCATION_TYPE_NAMES for entry in entries
    )

    malformed_relocation_count = sum(block.malformed_entry_count for block in blocks)

    return RelocationAnalysisData(
        relocation_directory_present=True,
        block_count=len(blocks),
        relocation_count=len(entries),
        mapped_relocation_count=sum(entry.is_mapped for entry in entries),
        executable_relocation_count=sum(entry.is_executable for entry in entries),
        writable_relocation_count=sum(entry.is_writable for entry in entries),
        malformed_relocation_count=(malformed_relocation_count),
        unknown_type_count=(unknown_type_count),
        relocation_types=(relocation_types),
        unusually_large_relocation_table=(len(entries) > LARGE_RELOCATION_TABLE_THRESHOLD),
        blocks=blocks,
    )


def _build_findings(
    data: RelocationAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative PE relocation findings."""
    findings: list[Finding] = []

    if not data.relocation_directory_present:
        return ()

    malformed_entries = tuple(
        entry for block in data.blocks for entry in block.entries if entry.malformed
    )

    if data.malformed_relocation_count:
        findings.append(
            Finding(
                title=("Malformed PE relocation entries detected"),
                description=(
                    "One or more PE base-relocation entries "
                    "reference invalid or unmapped image locations."
                ),
                category="pe-relocations",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="relocation",
                        value=(entry.relocation_type_name),
                        location=(entry.section_name or "unmapped"),
                        metadata={
                            "rva": entry.rva,
                            "virtual_address": (entry.virtual_address),
                        },
                    )
                    for entry in malformed_entries[:30]
                ),
                tags=(
                    "pe",
                    "relocations",
                    "malformed",
                ),
            )
        )

    unknown_entries = tuple(
        entry
        for block in data.blocks
        for entry in block.entries
        if entry.relocation_type not in RELOCATION_TYPE_NAMES
    )

    if unknown_entries:
        findings.append(
            Finding(
                title=("Unknown PE relocation types detected"),
                description=(
                    "The relocation table contains relocation "
                    "types not recognized by Astra's PE parser."
                ),
                category="pe-relocations",
                severity=Severity.LOW,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="relocation-type",
                        value=(entry.relocation_type_name),
                        location=(entry.section_name or "PE relocation directory"),
                        metadata={
                            "type": (entry.relocation_type),
                            "rva": entry.rva,
                        },
                    )
                    for entry in unknown_entries[:30]
                ),
                tags=(
                    "pe",
                    "relocations",
                    "unknown-type",
                ),
            )
        )

    if data.unusually_large_relocation_table:
        findings.append(
            Finding(
                title=("Unusually large PE relocation table detected"),
                description=(
                    "The binary contains an unusually large "
                    "number of base-relocation entries. This is "
                    "contextual metadata and should be correlated "
                    "with the binary type and compiler."
                ),
                category="pe-relocations",
                severity=Severity.INFO,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="relocation-count",
                        value=str(data.relocation_count),
                        location=("PE base-relocation directory"),
                    ),
                ),
                tags=(
                    "pe",
                    "relocations",
                    "large-table",
                ),
            )
        )

    return tuple(findings)


class RelocationsAnalyzer:
    """Analyze PE base-relocation metadata."""

    name = "relocations"
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
        """Analyze PE base-relocation directory metadata."""
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
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
                )

                analysis_data = _extract_data(pe)
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
