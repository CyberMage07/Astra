"""ELF relocation analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFRelocationAnalysisData,
    ELFRelocationEntry,
    ELFRelocationSection,
)

SHT_REL = "SHT_REL"
SHT_RELA = "SHT_RELA"
SHN_UNDEF = "SHN_UNDEF"


X86_64_RELOCATIONS: dict[int, str] = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    3: "R_X86_64_GOT32",
    4: "R_X86_64_PLT32",
    5: "R_X86_64_COPY",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
    9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32",
    11: "R_X86_64_32S",
    16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64",
    18: "R_X86_64_TPOFF64",
    19: "R_X86_64_TLSGD",
    20: "R_X86_64_TLSLD",
    21: "R_X86_64_DTPOFF32",
    22: "R_X86_64_GOTTPOFF",
    23: "R_X86_64_TPOFF32",
    24: "R_X86_64_PC64",
    25: "R_X86_64_GOTOFF64",
    26: "R_X86_64_GOTPC32",
    32: "R_X86_64_SIZE32",
    33: "R_X86_64_SIZE64",
    34: "R_X86_64_GOTPC32_TLSDESC",
    35: "R_X86_64_TLSDESC_CALL",
    36: "R_X86_64_TLSDESC",
    37: "R_X86_64_IRELATIVE",
    41: "R_X86_64_GOTPCRELX",
    42: "R_X86_64_REX_GOTPCRELX",
}

I386_RELOCATIONS: dict[int, str] = {
    0: "R_386_NONE",
    1: "R_386_32",
    2: "R_386_PC32",
    3: "R_386_GOT32",
    4: "R_386_PLT32",
    5: "R_386_COPY",
    6: "R_386_GLOB_DAT",
    7: "R_386_JMP_SLOT",
    8: "R_386_RELATIVE",
    9: "R_386_GOTOFF",
    10: "R_386_GOTPC",
    14: "R_386_TLS_TPOFF",
    35: "R_386_TLS_DTPMOD32",
    36: "R_386_TLS_DTPOFF32",
    37: "R_386_TLS_TPOFF32",
    42: "R_386_IRELATIVE",
}

AARCH64_RELOCATIONS: dict[int, str] = {
    0: "R_AARCH64_NONE",
    257: "R_AARCH64_ABS64",
    258: "R_AARCH64_ABS32",
    259: "R_AARCH64_ABS16",
    260: "R_AARCH64_PREL64",
    261: "R_AARCH64_PREL32",
    262: "R_AARCH64_PREL16",
    275: "R_AARCH64_ADR_PREL_PG_HI21",
    277: "R_AARCH64_ADD_ABS_LO12_NC",
    282: "R_AARCH64_JUMP26",
    283: "R_AARCH64_CALL26",
    1024: "R_AARCH64_COPY",
    1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT",
    1027: "R_AARCH64_RELATIVE",
    1032: "R_AARCH64_IRELATIVE",
}

ARM_RELOCATIONS: dict[int, str] = {
    0: "R_ARM_NONE",
    2: "R_ARM_ABS32",
    3: "R_ARM_REL32",
    21: "R_ARM_GLOB_DAT",
    22: "R_ARM_JUMP_SLOT",
    23: "R_ARM_RELATIVE",
    28: "R_ARM_CALL",
    29: "R_ARM_JUMP24",
    160: "R_ARM_IRELATIVE",
}

RISCV_RELOCATIONS: dict[int, str] = {
    0: "R_RISCV_NONE",
    1: "R_RISCV_32",
    2: "R_RISCV_64",
    3: "R_RISCV_RELATIVE",
    5: "R_RISCV_JUMP_SLOT",
    17: "R_RISCV_JAL",
    18: "R_RISCV_CALL",
    19: "R_RISCV_CALL_PLT",
    58: "R_RISCV_IRELATIVE",
}


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _as_int(
    value: object,
) -> int:
    """Convert parser values to non-negative integers."""
    if isinstance(
        value,
        bool,
    ):
        return int(value)

    if isinstance(
        value,
        int,
    ):
        return max(
            value,
            0,
        )

    return 0


def _signed_int(
    value: object,
) -> int | None:
    """Return an optional signed integer."""
    if isinstance(
        value,
        int,
    ):
        return value

    return None


def _machine(
    elf: ELFFile,
) -> str:
    """Return normalized ELF machine identifier."""
    return str(
        elf.header.get(
            "e_machine",
            "UNKNOWN",
        )
    )


def _relocation_type_name(
    machine: str,
    relocation_type: int,
) -> str:
    """Resolve common architecture-specific relocation names."""
    mapping: dict[
        int,
        str,
    ]

    if machine == "EM_X86_64":
        mapping = X86_64_RELOCATIONS

    elif machine == "EM_386":
        mapping = I386_RELOCATIONS

    elif machine == "EM_AARCH64":
        mapping = AARCH64_RELOCATIONS

    elif machine == "EM_ARM":
        mapping = ARM_RELOCATIONS

    elif machine == "EM_RISCV":
        mapping = RISCV_RELOCATIONS

    else:
        mapping = {}

    return mapping.get(
        relocation_type,
        f"UNKNOWN_{relocation_type}",
    )


def _section_type(
    section: RelocationSection,
) -> str:
    """Return relocation section type."""
    return str(
        section.header.get(
            "sh_type",
            "UNKNOWN",
        )
    )


def _is_rela(
    section: RelocationSection,
) -> bool:
    """Return whether a section uses RELA entries."""
    return _section_type(section) == SHT_RELA


def _linked_symbol_table(
    elf: ELFFile,
    section: RelocationSection,
) -> SymbolTableSection | None:
    """Resolve the symbol table referenced by a relocation section."""
    index = _as_int(
        section.header.get(
            "sh_link",
            0,
        )
    )

    try:
        linked = elf.get_section(index)
    except Exception:
        return None

    if not isinstance(
        linked,
        SymbolTableSection,
    ):
        return None

    return linked


def _symbol_name(
    symbol_table: SymbolTableSection | None,
    symbol_index: int,
) -> tuple[
    str | None,
    bool,
]:
    """Resolve relocation symbol name and import status."""
    if symbol_table is None or symbol_index <= 0:
        return (
            None,
            False,
        )

    try:
        symbol = symbol_table.get_symbol(symbol_index)
    except Exception:
        return (
            None,
            False,
        )

    name = str(
        getattr(
            symbol,
            "name",
            "",
        )
    ).strip()

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

    imported = str(section_index) == SHN_UNDEF

    return (
        name or None,
        imported,
    )


def _is_plt_related(
    section_name: str,
    relocation_type_name: str,
) -> bool:
    """Identify PLT-related relocations."""
    normalized_section = section_name.casefold()

    normalized_type = relocation_type_name.casefold()

    return (
        ".plt" in normalized_section
        or "jump_slot" in normalized_type
        or "jmp_slot" in normalized_type
        or "plt" in normalized_type
    )


def _is_got_related(
    section_name: str,
    relocation_type_name: str,
) -> bool:
    """Identify GOT-related relocations."""
    normalized_section = section_name.casefold()

    normalized_type = relocation_type_name.casefold()

    return ".got" in normalized_section or "got" in normalized_type or "glob_dat" in normalized_type


def _normalize_relocation(
    *,
    machine: str,
    section: RelocationSection,
    relocation: object,
    symbol_table: SymbolTableSection | None,
) -> ELFRelocationEntry:
    """Normalize one ELF relocation."""
    entry = getattr(
        relocation,
        "entry",
        None,
    )

    if entry is None:
        raise ValueError("Relocation entry structure missing")

    offset = _as_int(
        getattr(
            entry,
            "r_offset",
            0,
        )
    )

    relocation_type = _as_int(
        getattr(
            entry,
            "r_info_type",
            0,
        )
    )

    symbol_index = _as_int(
        getattr(
            entry,
            "r_info_sym",
            0,
        )
    )

    relocation_type_name = _relocation_type_name(
        machine,
        relocation_type,
    )

    (
        symbol_name,
        imported_symbol,
    ) = _symbol_name(
        symbol_table,
        symbol_index,
    )

    section_name = section.name or "(unnamed)"

    addend = None

    if _is_rela(section):
        addend = _signed_int(
            getattr(
                entry,
                "r_addend",
                None,
            )
        )

    return ELFRelocationEntry(
        section_name=section_name,
        offset=offset,
        relocation_type=(relocation_type),
        relocation_type_name=(relocation_type_name),
        symbol_index=symbol_index,
        symbol_name=symbol_name,
        addend=addend,
        has_symbol=(symbol_index > 0),
        imported_symbol=(imported_symbol),
        plt_related=(
            _is_plt_related(
                section_name,
                relocation_type_name,
            )
        ),
        got_related=(
            _is_got_related(
                section_name,
                relocation_type_name,
            )
        ),
        malformed=False,
    )


def _extract_section(
    *,
    elf: ELFFile,
    machine: str,
    section: RelocationSection,
) -> ELFRelocationSection:
    """Extract one ELF relocation section."""
    relocations: list[ELFRelocationEntry] = []

    malformed = 0

    symbol_table = _linked_symbol_table(
        elf,
        section,
    )

    try:
        entries = tuple(section.iter_relocations())
    except Exception:
        return ELFRelocationSection(
            name=(section.name or "(unnamed)"),
            section_type=(_section_type(section)),
            entry_count=0,
            malformed_entry_count=1,
            relocations=(),
        )

    for relocation in entries:
        try:
            relocations.append(
                _normalize_relocation(
                    machine=machine,
                    section=section,
                    relocation=(relocation),
                    symbol_table=(symbol_table),
                )
            )

        except Exception:
            malformed += 1

    return ELFRelocationSection(
        name=(section.name or "(unnamed)"),
        section_type=(_section_type(section)),
        entry_count=len(relocations),
        malformed_entry_count=(malformed),
        relocations=tuple(relocations),
    )


def _extract_sections(
    elf: ELFFile,
) -> tuple[ELFRelocationSection, ...]:
    """Extract all classic REL and RELA sections."""
    machine = _machine(elf)

    sections: list[ELFRelocationSection] = []

    for section in elf.iter_sections():
        if not isinstance(
            section,
            RelocationSection,
        ):
            continue

        sections.append(
            _extract_section(
                elf=elf,
                machine=machine,
                section=section,
            )
        )

    return tuple(sections)


def _build_data(
    elf: ELFFile,
) -> ELFRelocationAnalysisData:
    """Build normalized ELF relocation-analysis data."""
    sections = _extract_sections(elf)

    relocations = tuple(relocation for section in sections for relocation in section.relocations)

    relocation_types = tuple(
        sorted({relocation.relocation_type_name for relocation in relocations})
    )

    return ELFRelocationAnalysisData(
        relocation_sections_present=bool(sections),
        relocation_section_count=len(sections),
        relocation_count=len(relocations),
        rela_count=sum(
            len(section.relocations) for section in sections if section.section_type == SHT_RELA
        ),
        rel_count=sum(
            len(section.relocations) for section in sections if section.section_type == SHT_REL
        ),
        symbol_relocation_count=sum(relocation.has_symbol for relocation in relocations),
        imported_symbol_relocation_count=sum(
            relocation.imported_symbol for relocation in relocations
        ),
        plt_relocation_count=sum(relocation.plt_related for relocation in relocations),
        got_relocation_count=sum(relocation.got_related for relocation in relocations),
        malformed_relocation_count=sum(section.malformed_entry_count for section in sections),
        relocation_types=(relocation_types),
        sections=sections,
    )


class ELFRelocationsAnalyzer:
    """Analyze ELF relocation tables."""

    name = "elfrelocations"
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
        """Analyze ELF relocation structures."""
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

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.COMPLETED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                findings=(),
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
