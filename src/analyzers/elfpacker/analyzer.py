"""ELF packer and obfuscation analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFPackerAnalysisData,
    ELFPackerIndicator,
    Evidence,
    Finding,
    Severity,
)

HIGH_ENTROPY_THRESHOLD = 7.20
LOW_IMPORT_THRESHOLD = 8

KNOWN_PACKER_SECTION_NAMES: dict[str, str] = {
    ".upx0": "UPX",
    ".upx1": "UPX",
    ".upx2": "UPX",
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".packed": "generic-packer",
    ".packer": "generic-packer",
    ".aspack": "ASPack-like",
    ".petite": "Petite-like",
}


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _safe_int(
    value: object,
) -> int:
    """Normalize integer-like values."""
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    return 0


def _entropy(
    data: bytes,
) -> float:
    """Calculate Shannon entropy."""
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    length = len(data)

    import math

    result = 0.0

    for count in counts:
        if count == 0:
            continue

        probability = count / length
        result -= probability * math.log2(probability)

    return result


def _section_data(
    section: object,
) -> bytes:
    """Read section bytes safely."""
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

    return data if isinstance(data, bytes) else b""


def _collect_section_signals(
    elf: ELFFile,
) -> tuple[
    int,
    int,
    int,
    int,
    str | None,
]:
    """Collect entropy, RWX, and suspicious-name signals."""
    high_entropy_count = 0
    executable_high_entropy_count = 0
    rwx_count = 0
    suspicious_name_count = 0
    suspected_packer: str | None = None

    for section in elf.iter_sections():
        name = str(
            getattr(
                section,
                "name",
                "",
            )
        ).strip()

        header = getattr(
            section,
            "header",
            {},
        )

        flags = _safe_int(
            header.get(
                "sh_flags",
                0,
            )
        )

        executable = bool(flags & 0x4)

        writable = bool(flags & 0x1)

        allocatable = bool(flags & 0x2)

        if executable and writable and allocatable:
            rwx_count += 1

        data = _section_data(section)

        entropy = _entropy(data)

        if data and entropy >= HIGH_ENTROPY_THRESHOLD:
            high_entropy_count += 1

            if executable:
                executable_high_entropy_count += 1

        normalized_name = name.casefold()

        if normalized_name in KNOWN_PACKER_SECTION_NAMES:
            suspicious_name_count += 1

            if suspected_packer is None:
                suspected_packer = KNOWN_PACKER_SECTION_NAMES[normalized_name]

        elif any(
            fragment in normalized_name
            for fragment in (
                "upx",
                "pack",
                "crypt",
                "payload",
            )
        ):
            suspicious_name_count += 1

    return (
        high_entropy_count,
        executable_high_entropy_count,
        rwx_count,
        suspicious_name_count,
        suspected_packer,
    )


def _symbol_table_present(
    elf: ELFFile,
) -> bool:
    """Return whether the static symbol table exists."""
    section = elf.get_section_by_name(".symtab")

    return isinstance(
        section,
        SymbolTableSection,
    )


def _count_imports(
    elf: ELFFile,
) -> int:
    """Count dynamic undefined symbols."""
    section = elf.get_section_by_name(".dynsym")

    if not isinstance(
        section,
        SymbolTableSection,
    ):
        return 0

    count = 0

    try:
        for symbol in section.iter_symbols():
            entry = getattr(
                symbol,
                "entry",
                None,
            )

            section_index = getattr(
                entry,
                "st_shndx",
                None,
            )

            if str(section_index) == "SHN_UNDEF":
                count += 1

    except Exception:
        return count

    return count


def _count_relocations(
    elf: ELFFile,
) -> int:
    """Count relocation entries across relocation sections."""
    count = 0

    for section in elf.iter_sections():
        iter_relocations = getattr(
            section,
            "iter_relocations",
            None,
        )

        if not callable(iter_relocations):
            continue

        try:
            count += sum(1 for _ in iter_relocations())
        except Exception:
            continue

    return count


def _is_stripped(
    elf: ELFFile,
) -> bool:
    """Return whether the binary lacks a static symbol table."""
    return not _symbol_table_present(elf)


def _entry_point_unusual(
    elf: ELFFile,
) -> bool:
    """Detect an entry point outside executable sections."""
    entry = _safe_int(
        elf.header.get(
            "e_entry",
            0,
        )
    )

    if entry == 0:
        return False

    for section in elf.iter_sections():
        header = getattr(
            section,
            "header",
            {},
        )

        flags = _safe_int(
            header.get(
                "sh_flags",
                0,
            )
        )

        if not (flags & 0x4):
            continue

        address = _safe_int(
            header.get(
                "sh_addr",
                0,
            )
        )

        size = _safe_int(
            header.get(
                "sh_size",
                0,
            )
        )

        if address <= entry < address + size:
            return False

    return True


def _suspicious_dynamic_loading(
    elf: ELFFile,
) -> bool:
    """Detect combined dlopen+dlsym imports."""
    section = elf.get_section_by_name(".dynsym")

    if not isinstance(
        section,
        SymbolTableSection,
    ):
        return False

    names: set[str] = set()

    try:
        for symbol in section.iter_symbols():
            name = (
                str(
                    getattr(
                        symbol,
                        "name",
                        "",
                    )
                )
                .split(
                    "@",
                    1,
                )[0]
                .casefold()
            )

            if name:
                names.add(name)

    except Exception:
        return False

    return {
        "dlopen",
        "dlsym",
    }.issubset(names)


def _suspicious_layout(
    elf: ELFFile,
) -> bool:
    """Detect simple malformed or overlapping file-backed layout."""
    ranges: list[
        tuple[
            int,
            int,
        ]
    ] = []

    for section in elf.iter_sections():
        header = getattr(
            section,
            "header",
            {},
        )

        section_type = str(
            header.get(
                "sh_type",
                "",
            )
        )

        if section_type == "SHT_NOBITS":
            continue

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

        if size <= 0:
            continue

        ranges.append(
            (
                offset,
                offset + size,
            )
        )

    ranges.sort()

    for index in range(
        1,
        len(ranges),
    ):
        previous = ranges[index - 1]

        current = ranges[index]

        if current[0] < previous[1]:
            return True

    return False


def _likelihood(
    score: int,
) -> str:
    """Map packer score to a stable classification."""
    if score >= 80:
        return "strongly-packed"

    if score >= 60:
        return "likely-packed"

    if score >= 40:
        return "suspicious"

    if score >= 20:
        return "weak-indications"

    return "unlikely-packed"


def _build_data(
    elf: ELFFile,
) -> ELFPackerAnalysisData:
    """Build packer and obfuscation assessment data."""
    (
        high_entropy_count,
        executable_high_entropy_count,
        rwx_count,
        suspicious_name_count,
        suspected_packer,
    ) = _collect_section_signals(elf)

    stripped = _is_stripped(elf)

    symbol_table_present = _symbol_table_present(elf)

    import_count = _count_imports(elf)

    relocation_count = _count_relocations(elf)

    unusual_entry_point = _entry_point_unusual(elf)

    dynamic_loading = _suspicious_dynamic_loading(elf)

    layout = _suspicious_layout(elf)

    indicators: list[ELFPackerIndicator] = []

    known_signature = suspected_packer is not None

    indicators.append(
        ELFPackerIndicator(
            name="known-packer-signature",
            category="packer-signature",
            description=("Known or strongly packer-associated ELF section naming was detected."),
            weight=40,
            triggered=known_signature,
            evidence=((suspected_packer,) if suspected_packer else ()),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="high-entropy-executable-sections",
            category="entropy",
            description=("Executable sections contain unusually high-entropy data."),
            weight=20,
            triggered=(executable_high_entropy_count > 0),
            evidence=(
                (str(executable_high_entropy_count),) if executable_high_entropy_count else ()
            ),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="rwx-sections",
            category="permissions",
            description=("Writable and executable ELF sections were detected."),
            weight=15,
            triggered=(rwx_count > 0),
            evidence=((str(rwx_count),) if rwx_count else ()),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="suspicious-section-names",
            category="section-layout",
            description=("Packing- or obfuscation-like section names were detected."),
            weight=15,
            triggered=(suspicious_name_count > 0),
            evidence=((str(suspicious_name_count),) if suspicious_name_count else ()),
        )
    )

    sparse_symbols = bool(stripped and import_count < LOW_IMPORT_THRESHOLD)

    indicators.append(
        ELFPackerIndicator(
            name="stripped-sparse-symbols",
            category="symbols",
            description=("The ELF binary is stripped and has very few dynamic imports."),
            weight=10,
            triggered=(sparse_symbols),
            evidence=((f"imports={import_count}",) if sparse_symbols else ()),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="unusual-entry-point",
            category="entry-point",
            description=("The ELF entry point does not fall inside a known executable section."),
            weight=10,
            triggered=(unusual_entry_point),
            evidence=(),
        )
    )

    unusual_relocations = bool(relocation_count == 0 and import_count > 0)

    indicators.append(
        ELFPackerIndicator(
            name="unusual-relocation-profile",
            category="relocations",
            description=("Imported symbols are present while no relocation entries were observed."),
            weight=10,
            triggered=(unusual_relocations),
            evidence=(
                (
                    f"imports={import_count}",
                    f"relocations={relocation_count}",
                )
                if unusual_relocations
                else ()
            ),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="runtime-dynamic-loading",
            category="dynamic-loading",
            description=("The ELF binary imports both dlopen and dlsym."),
            weight=5,
            triggered=(dynamic_loading),
            evidence=(
                (
                    "dlopen",
                    "dlsym",
                )
                if dynamic_loading
                else ()
            ),
        )
    )

    indicators.append(
        ELFPackerIndicator(
            name="suspicious-layout",
            category="section-layout",
            description=("Overlapping file-backed ELF section ranges were detected."),
            weight=10,
            triggered=layout,
            evidence=(),
        )
    )

    score = min(
        100,
        sum(indicator.weight for indicator in indicators if indicator.triggered),
    )

    evidence_count = sum(indicator.triggered for indicator in indicators)

    return ELFPackerAnalysisData(
        packed_score=score,
        packed_likelihood=(_likelihood(score)),
        suspected_packer=(suspected_packer),
        known_packer_signature=(known_signature),
        high_entropy_section_count=(high_entropy_count),
        executable_high_entropy_count=(executable_high_entropy_count),
        rwx_section_count=(rwx_count),
        suspicious_section_name_count=(suspicious_name_count),
        stripped=stripped,
        symbol_table_present=(symbol_table_present),
        import_count=(import_count),
        relocation_count=(relocation_count),
        unusual_entry_point=(unusual_entry_point),
        suspicious_dynamic_loading=(dynamic_loading),
        suspicious_layout=layout,
        evidence_count=(evidence_count),
        indicators=tuple(indicators),
    )


def _build_findings(
    data: ELFPackerAnalysisData,
) -> tuple[Finding, ...]:
    """Generate one aggregate packing finding when warranted."""
    if data.packed_score < 40:
        return ()

    severity = Severity.HIGH if data.packed_score >= 80 else Severity.MEDIUM

    triggered = tuple(indicator for indicator in data.indicators if indicator.triggered)

    return (
        Finding(
            title=("ELF packing or obfuscation indicators detected"),
            description=(
                "Multiple ELF structural indicators are "
                "consistent with packing, compression, "
                "obfuscation, or self-modifying behavior. "
                "The result is heuristic and should be "
                "correlated with additional evidence."
            ),
            category="elf-packing",
            severity=severity,
            confidence=min(
                95,
                55 + data.evidence_count * 5,
            ),
            evidence=tuple(
                Evidence(
                    kind="elf-packer-indicator",
                    value=indicator.name,
                    location="ELF structure",
                    metadata={
                        "weight": (indicator.weight),
                        "category": (indicator.category),
                    },
                )
                for indicator in triggered
            ),
            tags=(
                "elf",
                "packing",
                "obfuscation",
            ),
        ),
    )


class ELFPackerAnalyzer:
    """Assess ELF binaries for packing and obfuscation."""

    name = "elfpacker"
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
        """Analyze ELF packing and obfuscation indicators."""
        started_at = datetime.now(UTC)

        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            with resolved_path.open("rb") as file_object:
                elf = _load_elf(file_object)

                analysis_data = _build_data(elf)

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
