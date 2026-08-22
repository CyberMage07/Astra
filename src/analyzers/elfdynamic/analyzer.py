"""ELF dynamic linking, PLT, GOT, and binding analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFDynamicLinkingAnalysisData,
    ELFDynamicSectionInfo,
    Evidence,
    Finding,
    Severity,
)

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

PT_GNU_RELRO = "PT_GNU_RELRO"

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _safe_int(
    value: object,
) -> int:
    """Normalize integer-like ELF values."""
    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    return 0


def _section_info(
    section: object,
) -> ELFDynamicSectionInfo:
    """Normalize one PLT/GOT-related ELF section."""
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

    entry_size = _safe_int(
        header.get(
            "sh_entsize",
            0,
        )
    )

    flags = _safe_int(
        header.get(
            "sh_flags",
            0,
        )
    )

    writable = bool(flags & SHF_WRITE)

    executable = bool(flags & SHF_EXECINSTR)

    allocatable = bool(flags & SHF_ALLOC)

    entry_count = size // entry_size if entry_size > 0 else 0

    return ELFDynamicSectionInfo(
        name=name,
        section_type=section_type,
        address=address,
        offset=offset,
        size=size,
        entry_size=entry_size,
        flags=flags,
        writable=writable,
        executable=executable,
        allocatable=allocatable,
        entry_count=entry_count,
    )


def _collect_linking_sections(
    elf: ELFFile,
) -> tuple[
    tuple[ELFDynamicSectionInfo, ...],
    int,
]:
    """Collect PLT/GOT-related ELF sections."""
    interesting_names = {
        ".plt",
        ".plt.got",
        ".plt.sec",
        ".got",
        ".got.plt",
    }

    sections: list[ELFDynamicSectionInfo] = []

    malformed = 0

    for section in elf.iter_sections():
        name = str(
            getattr(
                section,
                "name",
                "",
            )
        )

        if name not in interesting_names:
            continue

        try:
            sections.append(_section_info(section))
        except Exception:
            malformed += 1

    return (
        tuple(sections),
        malformed,
    )


def _dynamic_tags(
    elf: ELFFile,
) -> tuple[
    dict[str, object],
    int,
]:
    """Collect dynamic tags needed for PLT/GOT analysis."""
    tags: dict[str, object] = {}

    malformed = 0

    for section in elf.iter_sections():
        if not isinstance(
            section,
            DynamicSection,
        ):
            continue

        try:
            for tag in section.iter_tags():
                try:
                    name = str(tag.entry.d_tag)

                    tags[name] = tag

                except Exception:
                    malformed += 1

        except Exception:
            malformed += 1

    return (
        tags,
        malformed,
    )


def _tag_value(
    tag: object | None,
) -> int | None:
    """Extract integer dynamic-tag value."""
    if tag is None:
        return None

    entry = getattr(
        tag,
        "entry",
        None,
    )

    if entry is None:
        return None

    for attribute in (
        "d_ptr",
        "d_val",
    ):
        value = getattr(
            entry,
            attribute,
            None,
        )

        if isinstance(
            value,
            int,
        ):
            return value

    return None


def _has_relro(
    elf: ELFFile,
) -> bool:
    """Return whether PT_GNU_RELRO is present."""
    try:
        for segment in elf.iter_segments():
            header = getattr(
                segment,
                "header",
                {},
            )

            if (
                str(
                    header.get(
                        "p_type",
                        "",
                    )
                )
                == PT_GNU_RELRO
            ):
                return True

    except Exception:
        return False

    return False


def _bind_now_from_tags(
    tags: dict[str, object],
) -> bool:
    """Detect eager binding from dynamic tags."""
    if "DT_BIND_NOW" in tags:
        return True

    flags_tag = tags.get("DT_FLAGS")

    flags = _tag_value(flags_tag)

    if flags is not None and flags & DF_BIND_NOW:
        return True

    flags_1_tag = tags.get("DT_FLAGS_1")

    flags_1 = _tag_value(flags_1_tag)

    return bool(flags_1 is not None and flags_1 & DF_1_NOW)


def _plt_relocation_type(
    tags: dict[str, object],
) -> str | None:
    """Normalize DT_PLTREL type."""
    tag = tags.get("DT_PLTREL")

    value = _tag_value(tag)

    if value is None:
        return None

    if value == 7:
        return "DT_RELA"

    if value == 17:
        return "DT_REL"

    return str(value)


def _plt_relocation_count(
    elf: ELFFile,
) -> int:
    """Count relocation entries associated with PLT binding."""
    count = 0

    candidate_names = {
        ".rela.plt",
        ".rel.plt",
        ".rela.plt.sec",
        ".rel.plt.sec",
    }

    for section in elf.iter_sections():
        name = str(
            getattr(
                section,
                "name",
                "",
            )
        )

        if name not in candidate_names:
            continue

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


def _estimate_plt_entries(
    sections: tuple[ELFDynamicSectionInfo, ...],
    relocation_count: int,
) -> int:
    """Estimate the number of callable PLT entries."""
    candidates = [
        section.entry_count
        for section in sections
        if (
            section.name
            in {
                ".plt",
                ".plt.sec",
            }
            and section.entry_count > 0
        )
    ]

    if candidates:
        return max(
            max(candidates),
            relocation_count,
        )

    return relocation_count


def _estimate_got_entries(
    sections: tuple[ELFDynamicSectionInfo, ...],
    elf_class: int,
) -> int:
    """Estimate GOT entry count from section sizes."""
    pointer_size = 8 if elf_class == 64 else 4

    total_size = sum(
        section.size
        for section in sections
        if section.name
        in {
            ".got",
            ".got.plt",
        }
    )

    if pointer_size <= 0:
        return 0

    return total_size // pointer_size


def _writable_got(
    sections: tuple[ELFDynamicSectionInfo, ...],
) -> bool:
    """Return whether a GOT-related section is writable."""
    return any(
        section.writable
        for section in sections
        if section.name
        in {
            ".got",
            ".got.plt",
        }
    )


def _build_data(
    elf: ELFFile,
) -> ELFDynamicLinkingAnalysisData:
    """Build ELF dynamic-linking analysis data."""
    (
        sections,
        malformed_sections,
    ) = _collect_linking_sections(elf)

    (
        tags,
        malformed_tags,
    ) = _dynamic_tags(elf)

    plt_present = any(section.name == ".plt" for section in sections)

    plt_got_present = any(section.name == ".plt.got" for section in sections)

    plt_sec_present = any(section.name == ".plt.sec" for section in sections)

    got_present = any(section.name == ".got" for section in sections)

    got_plt_present = any(section.name == ".got.plt" for section in sections)

    plt_sections = tuple(section for section in sections if section.name.startswith(".plt"))

    got_sections = tuple(
        section
        for section in sections
        if section.name
        in {
            ".got",
            ".got.plt",
        }
    )

    bind_now = _bind_now_from_tags(tags)

    relro = _has_relro(elf)

    full_relro = bool(relro and bind_now)

    writable_got = _writable_got(sections)

    plt_relocation_count = _plt_relocation_count(elf)

    plt_entry_count = _estimate_plt_entries(
        sections,
        plt_relocation_count,
    )

    elf_class = _safe_int(
        getattr(
            elf,
            "elfclass",
            0,
        )
    )

    got_entry_estimate = _estimate_got_entries(
        sections,
        elf_class,
    )

    plt_got_address = _tag_value(tags.get("DT_PLTGOT"))

    jmprel_address = _tag_value(tags.get("DT_JMPREL"))

    plt_relocation_size = _tag_value(tags.get("DT_PLTRELSZ")) or 0

    plt_relocation_type = _plt_relocation_type(tags)

    dynamic_linking_present = bool(
        tags or plt_present or plt_sec_present or got_present or got_plt_present
    )

    lazy_binding = bool(dynamic_linking_present and not bind_now and plt_relocation_count > 0)

    suspicious_dynamic_linking = bool(lazy_binding and writable_got and not full_relro)

    return ELFDynamicLinkingAnalysisData(
        dynamic_linking_present=(dynamic_linking_present),
        plt_present=plt_present,
        plt_got_present=(plt_got_present),
        plt_sec_present=(plt_sec_present),
        got_present=got_present,
        got_plt_present=(got_plt_present),
        plt_section_count=len(plt_sections),
        got_section_count=len(got_sections),
        plt_entry_count=(plt_entry_count),
        got_entry_estimate=(got_entry_estimate),
        plt_relocation_count=(plt_relocation_count),
        plt_got_address=(plt_got_address),
        jmprel_address=(jmprel_address),
        plt_relocation_size=(plt_relocation_size),
        plt_relocation_type=(plt_relocation_type),
        bind_now=bind_now,
        lazy_binding=(lazy_binding),
        relro=relro,
        full_relro=(full_relro),
        writable_got=(writable_got),
        malformed_entry_count=(malformed_sections + malformed_tags),
        suspicious_dynamic_linking=(suspicious_dynamic_linking),
        sections=sections,
    )


def _build_findings(
    data: ELFDynamicLinkingAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative PLT/GOT security findings."""
    findings: list[Finding] = []

    if data.suspicious_dynamic_linking:
        findings.append(
            Finding(
                title=("Writable GOT with lazy binding detected"),
                description=(
                    "The ELF binary uses lazy dynamic binding "
                    "while GOT-related storage remains writable "
                    "and full RELRO is not active. This weakens "
                    "dynamic-linking hardening and can increase "
                    "the impact of memory-corruption vulnerabilities."
                ),
                category=("elf-dynamic-linking"),
                severity=(Severity.LOW),
                confidence=75,
                evidence=(
                    Evidence(
                        kind=("elf-dynamic-linking"),
                        value=("lazy-binding+writable-got"),
                        location=("PLT/GOT"),
                        metadata={
                            "bind_now": (data.bind_now),
                            "relro": (data.relro),
                            "full_relro": (data.full_relro),
                            "writable_got": (data.writable_got),
                        },
                    ),
                ),
                tags=(
                    "elf",
                    "plt",
                    "got",
                    "hardening",
                ),
            )
        )

    if data.malformed_entry_count > 0:
        findings.append(
            Finding(
                title=("Malformed ELF dynamic-linking metadata detected"),
                description=(
                    "One or more PLT/GOT or dynamic-tag structures could not be normalized cleanly."
                ),
                category=("elf-dynamic-linking"),
                severity=(Severity.MEDIUM),
                confidence=70,
                evidence=(
                    Evidence(
                        kind=("elf-dynamic-linking"),
                        value=str(data.malformed_entry_count),
                        location=("dynamic metadata"),
                    ),
                ),
                tags=(
                    "elf",
                    "dynamic-linking",
                    "malformed",
                ),
            )
        )

    return tuple(findings)


class ELFDynamicLinkingAnalyzer:
    """Analyze ELF dynamic linking, PLT, GOT, and binding behavior."""

    name = "elfdynamic"
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
        """Analyze ELF dynamic-linking structures."""
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
