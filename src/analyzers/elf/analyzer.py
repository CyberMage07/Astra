"""Static analysis for ELF executables and shared objects."""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import InterpSegment

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFAnalysisData,
    ELFDynamicInfo,
    ELFHeaderInfo,
    ELFSection,
    ELFSecurityInfo,
    ELFSegment,
    Evidence,
    Finding,
    Severity,
)

ET_DYN = "ET_DYN"
ET_EXEC = "ET_EXEC"

PT_INTERP = "PT_INTERP"
PT_DYNAMIC = "PT_DYNAMIC"
PT_GNU_STACK = "PT_GNU_STACK"
PT_GNU_RELRO = "PT_GNU_RELRO"

DT_NEEDED = "DT_NEEDED"
DT_SONAME = "DT_SONAME"
DT_RPATH = "DT_RPATH"
DT_RUNPATH = "DT_RUNPATH"
DT_BIND_NOW = "DT_BIND_NOW"
DT_FLAGS = "DT_FLAGS"
DT_FLAGS_1 = "DT_FLAGS_1"

DF_BIND_NOW = 0x00000008
DF_1_NOW = 0x00000001


def _as_int(value: object) -> int:
    """Convert pyelftools values to integers safely."""
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    return 0


def _header_value(
    elf: ELFFile,
    key: str,
    default: object = 0,
) -> object:
    """Read one normalized ELF header value."""
    return elf.header.get(
        key,
        default,
    )


def _ident_value(
    elf: ELFFile,
    key: str,
    default: object,
) -> object:
    """Read one value from the ELF e_ident structure."""
    ident = _header_value(
        elf,
        "e_ident",
        {},
    )

    if isinstance(
        ident,
        Mapping,
    ):
        return ident.get(
            key,
            default,
        )

    return default


def _normalize_machine(
    machine: object,
) -> str:
    """Return a readable ELF machine value."""
    value = str(machine)

    mappings = {
        "EM_X86_64": "x86-64",
        "EM_386": "x86",
        "EM_AARCH64": "ARM64",
        "EM_ARM": "ARM",
        "EM_RISCV": "RISC-V",
        "EM_MIPS": "MIPS",
        "EM_PPC": "PowerPC",
        "EM_PPC64": "PowerPC64",
    }

    return mappings.get(
        value,
        value,
    )


def _normalize_os_abi(
    os_abi: object,
) -> str:
    """Return a readable ELF OS ABI."""
    value = str(os_abi)

    mappings = {
        "ELFOSABI_SYSV": "System V",
        "ELFOSABI_LINUX": "Linux",
        "ELFOSABI_FREEBSD": "FreeBSD",
        "ELFOSABI_NETBSD": "NetBSD",
        "ELFOSABI_SOLARIS": "Solaris",
    }

    return mappings.get(
        value,
        value,
    )


def _extract_header(
    elf: ELFFile,
) -> ELFHeaderInfo:
    """Extract normalized ELF header information."""
    return ELFHeaderInfo(
        architecture_bits=elf.elfclass,
        endianness=("little" if elf.little_endian else "big"),
        elf_type=str(
            _header_value(
                elf,
                "e_type",
                "unknown",
            )
        ),
        machine=_normalize_machine(
            _header_value(
                elf,
                "e_machine",
                "unknown",
            )
        ),
        os_abi=_normalize_os_abi(
            _ident_value(
                elf,
                "EI_OSABI",
                "unknown",
            )
        ),
        abi_version=_as_int(
            _ident_value(
                elf,
                "EI_ABIVERSION",
                0,
            )
        ),
        elf_version=_as_int(
            _header_value(
                elf,
                "e_version",
                0,
            )
        ),
        entry_point=_as_int(
            _header_value(
                elf,
                "e_entry",
                0,
            )
        ),
        program_header_offset=_as_int(
            _header_value(
                elf,
                "e_phoff",
                0,
            )
        ),
        section_header_offset=_as_int(
            _header_value(
                elf,
                "e_shoff",
                0,
            )
        ),
        program_header_count=_as_int(
            _header_value(
                elf,
                "e_phnum",
                0,
            )
        ),
        section_header_count=_as_int(
            _header_value(
                elf,
                "e_shnum",
                0,
            )
        ),
        flags=_as_int(
            _header_value(
                elf,
                "e_flags",
                0,
            )
        ),
    )


def _extract_sections(
    elf: ELFFile,
) -> tuple[
    tuple[ELFSection, ...],
    int,
]:
    """Extract normalized ELF sections."""
    sections: list[ELFSection] = []

    malformed = 0

    for index, section in enumerate(elf.iter_sections()):
        try:
            header = section.header
            flags = _as_int(
                header.get(
                    "sh_flags",
                    0,
                )
            )

            sections.append(
                ELFSection(
                    index=index,
                    name=section.name or "(unnamed)",
                    section_type=str(
                        header.get(
                            "sh_type",
                            "unknown",
                        )
                    ),
                    address=_as_int(
                        header.get(
                            "sh_addr",
                            0,
                        )
                    ),
                    offset=_as_int(
                        header.get(
                            "sh_offset",
                            0,
                        )
                    ),
                    size=_as_int(
                        header.get(
                            "sh_size",
                            0,
                        )
                    ),
                    entry_size=_as_int(
                        header.get(
                            "sh_entsize",
                            0,
                        )
                    ),
                    flags=flags,
                    alignment=_as_int(
                        header.get(
                            "sh_addralign",
                            0,
                        )
                    ),
                    executable=bool(flags & SH_FLAGS.SHF_EXECINSTR),
                    writable=bool(flags & SH_FLAGS.SHF_WRITE),
                    allocatable=bool(flags & SH_FLAGS.SHF_ALLOC),
                )
            )

        except Exception:
            malformed += 1

    return (
        tuple(sections),
        malformed,
    )


def _extract_segments(
    elf: ELFFile,
) -> tuple[
    tuple[ELFSegment, ...],
    int,
]:
    """Extract normalized ELF program-header segments."""
    segments: list[ELFSegment] = []

    malformed = 0

    for index, segment in enumerate(elf.iter_segments()):
        try:
            header = segment.header

            flags = _as_int(
                header.get(
                    "p_flags",
                    0,
                )
            )

            segments.append(
                ELFSegment(
                    index=index,
                    segment_type=str(
                        header.get(
                            "p_type",
                            "unknown",
                        )
                    ),
                    offset=_as_int(
                        header.get(
                            "p_offset",
                            0,
                        )
                    ),
                    virtual_address=_as_int(
                        header.get(
                            "p_vaddr",
                            0,
                        )
                    ),
                    physical_address=_as_int(
                        header.get(
                            "p_paddr",
                            0,
                        )
                    ),
                    file_size=_as_int(
                        header.get(
                            "p_filesz",
                            0,
                        )
                    ),
                    memory_size=_as_int(
                        header.get(
                            "p_memsz",
                            0,
                        )
                    ),
                    flags=flags,
                    alignment=_as_int(
                        header.get(
                            "p_align",
                            0,
                        )
                    ),
                    readable=bool(flags & P_FLAGS.PF_R),
                    writable=bool(flags & P_FLAGS.PF_W),
                    executable=bool(flags & P_FLAGS.PF_X),
                )
            )

        except Exception:
            malformed += 1

    return (
        tuple(segments),
        malformed,
    )


def _extract_interpreter(
    elf: ELFFile,
) -> str | None:
    """Extract the ELF runtime interpreter path."""
    for segment in elf.iter_segments():
        if not isinstance(
            segment,
            InterpSegment,
        ):
            continue

        try:
            value = segment.get_interp_name()

            if value:
                return str(value)

        except Exception:
            return None

    return None


def _dynamic_sections(
    elf: ELFFile,
) -> tuple[DynamicSection, ...]:
    """Return ELF dynamic sections."""
    return tuple(
        section
        for section in elf.iter_sections()
        if isinstance(
            section,
            DynamicSection,
        )
    )


def _extract_dynamic(
    elf: ELFFile,
) -> ELFDynamicInfo:
    """Extract dynamic-linking information."""
    dynamic_sections = _dynamic_sections(elf)

    needed: list[str] = []

    soname: str | None = None
    rpath: str | None = None
    runpath: str | None = None

    bind_now = False
    dynamic_entry_count = 0

    for section in dynamic_sections:
        for tag in section.iter_tags():
            dynamic_entry_count += 1

            tag_name = str(tag.entry.d_tag)

            if tag_name == DT_NEEDED:
                needed.append(
                    str(
                        getattr(
                            tag,
                            "needed",
                            "",
                        )
                    )
                )

            elif tag_name == DT_SONAME:
                soname = str(
                    getattr(
                        tag,
                        "soname",
                        "",
                    )
                )

            elif tag_name == DT_RPATH:
                rpath = str(
                    getattr(
                        tag,
                        "rpath",
                        "",
                    )
                )

            elif tag_name == DT_RUNPATH:
                runpath = str(
                    getattr(
                        tag,
                        "runpath",
                        "",
                    )
                )

            elif tag_name == DT_BIND_NOW:
                bind_now = True

            elif tag_name == DT_FLAGS:
                flags = _as_int(
                    tag.entry.get(
                        "d_val",
                        0,
                    )
                )

                if flags & DF_BIND_NOW:
                    bind_now = True

            elif tag_name == DT_FLAGS_1:
                flags = _as_int(
                    tag.entry.get(
                        "d_val",
                        0,
                    )
                )

                if flags & DF_1_NOW:
                    bind_now = True

    return ELFDynamicInfo(
        dynamically_linked=bool(dynamic_sections),
        interpreter=(_extract_interpreter(elf)),
        needed_libraries=tuple(library for library in needed if library),
        soname=(soname or None),
        rpath=(rpath or None),
        runpath=(runpath or None),
        bind_now=bind_now,
        dynamic_entry_count=(dynamic_entry_count),
    )


def _has_segment(
    segments: tuple[ELFSegment, ...],
    segment_type: str,
) -> bool:
    """Return whether a segment type exists."""
    return any(segment.segment_type == segment_type for segment in segments)


def _gnu_stack_segment(
    segments: tuple[ELFSegment, ...],
) -> ELFSegment | None:
    """Return PT_GNU_STACK when present."""
    for segment in segments:
        if segment.segment_type == PT_GNU_STACK:
            return segment

    return None


def _is_stripped(
    elf: ELFFile,
) -> bool:
    """Return whether conventional symbol information is absent."""
    symtab = elf.get_section_by_name(".symtab")

    return not isinstance(
        symtab,
        SymbolTableSection,
    )


def _has_stack_canary(
    elf: ELFFile,
) -> bool:
    """Detect references to common stack-canary failure handlers."""
    for section in elf.iter_sections():
        if not isinstance(
            section,
            SymbolTableSection,
        ):
            continue

        try:
            for symbol in section.iter_symbols():
                if symbol.name in {
                    "__stack_chk_fail",
                    "__stack_chk_guard",
                }:
                    return True

        except Exception:
            continue

    return False


def _extract_security(
    elf: ELFFile,
    header: ELFHeaderInfo,
    segments: tuple[ELFSegment, ...],
    dynamic: ELFDynamicInfo,
) -> ELFSecurityInfo:
    """Extract ELF hardening properties."""
    stack_segment = _gnu_stack_segment(segments)

    executable_stack = bool(stack_segment is not None and stack_segment.executable)

    nx_enabled = bool(stack_segment is not None and not stack_segment.executable)

    relro = _has_segment(
        segments,
        PT_GNU_RELRO,
    )

    full_relro = bool(relro and dynamic.bind_now)

    pie = bool(header.elf_type == ET_DYN and dynamic.interpreter)

    return ELFSecurityInfo(
        pie=pie,
        nx_enabled=nx_enabled,
        executable_stack=(executable_stack),
        relro=relro,
        full_relro=full_relro,
        bind_now=dynamic.bind_now,
        stripped=_is_stripped(elf),
        has_stack_canary=(_has_stack_canary(elf)),
        has_rpath=(dynamic.rpath is not None),
        has_runpath=(dynamic.runpath is not None),
    )


def _build_findings(
    data: ELFAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative ELF security findings."""
    findings: list[Finding] = []

    security = data.security
    dynamic = data.dynamic

    if security.executable_stack:
        findings.append(
            Finding(
                title=("Executable ELF stack detected"),
                description=(
                    "PT_GNU_STACK is marked executable. This reduces exploit-mitigation protection."
                ),
                category=("elf-hardening"),
                severity=Severity.MEDIUM,
                confidence=90,
                evidence=(
                    Evidence(
                        kind=("elf-security"),
                        value=("executable-stack"),
                        location=("PT_GNU_STACK"),
                    ),
                ),
                tags=(
                    "elf",
                    "nx",
                    "executable-stack",
                ),
            )
        )

    if dynamic.rpath:
        findings.append(
            Finding(
                title=("ELF RPATH configured"),
                description=(
                    "The binary contains DT_RPATH. "
                    "Runtime library search paths "
                    "can become security-sensitive "
                    "when writable or attacker-"
                    "controlled directories are used."
                ),
                category=("elf-linking"),
                severity=Severity.LOW,
                confidence=70,
                evidence=(
                    Evidence(
                        kind=("elf-dynamic"),
                        value=(dynamic.rpath),
                        location=("DT_RPATH"),
                    ),
                ),
                tags=(
                    "elf",
                    "rpath",
                ),
            )
        )

    return tuple(findings)


def _build_data(
    elf: ELFFile,
) -> ELFAnalysisData:
    """Build normalized ELF analysis data."""
    header = _extract_header(elf)

    (
        sections,
        malformed_sections,
    ) = _extract_sections(elf)

    (
        segments,
        malformed_segments,
    ) = _extract_segments(elf)

    dynamic = _extract_dynamic(elf)

    security = _extract_security(
        elf,
        header,
        segments,
        dynamic,
    )

    return ELFAnalysisData(
        elf_present=True,
        header=header,
        sections=sections,
        segments=segments,
        section_count=len(sections),
        segment_count=len(segments),
        dynamic=dynamic,
        security=security,
        malformed=bool(malformed_sections or malformed_segments),
        malformed_section_count=(malformed_sections),
        malformed_segment_count=(malformed_segments),
    )


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


class ELFAnalyzer:
    """Perform foundational static analysis of ELF files."""

    name = "elf"
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
        """Analyze one ELF sample."""
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

        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            error_name = type(error).__name__

            recoverable = not isinstance(
                error,
                (
                    ValueError,
                    EOFError,
                ),
            )

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.PARTIAL if recoverable else AnalysisStatus.FAILED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                errors=(
                    AnalyzerError(
                        error_type=(error_name),
                        message=str(error),
                        recoverable=(recoverable),
                    ),
                ),
            )
