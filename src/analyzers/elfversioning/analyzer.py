"""ELF GNU symbol versioning and ABI dependency analysis for Astra."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import (
    GNUVerDefSection,
    GNUVerNeedSection,
    GNUVerSymSection,
)
from elftools.elf.sections import SymbolTableSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFSymbolVersionBinding,
    ELFSymbolVersionDefinition,
    ELFSymbolVersionRequirement,
    ELFVersioningAnalysisData,
    Evidence,
    Finding,
    Severity,
)

_VERSION_PATTERN = re.compile(r"^(?P<prefix>[A-Za-z0-9]+)_(?P<version>[0-9]+(?:\.[0-9]+)*)$")


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


def _version_key(
    value: str,
) -> tuple[int, ...]:
    """Convert a version string into a sortable integer tuple."""
    match = _VERSION_PATTERN.match(value.strip())

    if match is None:
        return ()

    return tuple(int(part) for part in match.group("version").split("."))


def _highest_version(
    values: set[str],
) -> str | None:
    """Return the numerically highest version string."""
    candidates = [value for value in values if _version_key(value)]

    if not candidates:
        return None

    return max(
        candidates,
        key=_version_key,
    )


def _extract_requirements(
    section: GNUVerNeedSection | None,
) -> tuple[
    tuple[ELFSymbolVersionRequirement, ...],
    dict[int, tuple[str, str]],
    int,
]:
    """Extract version requirements and build an index map."""
    if section is None:
        return (
            (),
            {},
            0,
        )

    requirements: list[ELFSymbolVersionRequirement] = []

    index_map: dict[
        int,
        tuple[
            str,
            str,
        ],
    ] = {}

    malformed = 0

    try:
        for version, auxiliaries in section.iter_versions():
            library = str(
                getattr(
                    version,
                    "name",
                    "",
                )
                or ""
            ).strip()

            for auxiliary in auxiliaries:
                try:
                    version_name = str(
                        getattr(
                            auxiliary,
                            "name",
                            "",
                        )
                        or ""
                    ).strip()

                    entry = getattr(
                        auxiliary,
                        "entry",
                        None,
                    )

                    version_index = _safe_int(
                        getattr(
                            entry,
                            "vna_other",
                            0,
                        )
                    )

                    hidden = bool(version_index & 0x8000)

                    normalized_index = version_index & 0x7FFF

                    if not version_name:
                        malformed += 1
                        continue

                    requirement = ELFSymbolVersionRequirement(
                        library=(library or "(unknown)"),
                        version=version_name,
                        version_index=(normalized_index),
                        hidden=hidden,
                    )

                    requirements.append(requirement)

                    if normalized_index > 1:
                        index_map[normalized_index] = (
                            requirement.library,
                            requirement.version,
                        )

                except Exception:
                    malformed += 1

    except Exception:
        malformed += 1

    return (
        tuple(requirements),
        index_map,
        malformed,
    )


def _extract_definitions(
    section: GNUVerDefSection | None,
) -> tuple[
    tuple[ELFSymbolVersionDefinition, ...],
    dict[int, str],
    int,
]:
    """Extract symbol-version definitions and index mapping."""
    if section is None:
        return (
            (),
            {},
            0,
        )

    definitions: list[ELFSymbolVersionDefinition] = []

    index_map: dict[
        int,
        str,
    ] = {}

    malformed = 0

    try:
        for version, auxiliaries in section.iter_versions():
            try:
                entry = getattr(
                    version,
                    "entry",
                    None,
                )

                version_index = _safe_int(
                    getattr(
                        entry,
                        "vd_ndx",
                        0,
                    )
                )

                flags = _safe_int(
                    getattr(
                        entry,
                        "vd_flags",
                        0,
                    )
                )

                auxiliary_list = list(auxiliaries)

                if not auxiliary_list:
                    malformed += 1
                    continue

                version_name = str(
                    getattr(
                        auxiliary_list[0],
                        "name",
                        "",
                    )
                    or ""
                ).strip()

                if not version_name:
                    malformed += 1
                    continue

                definition = ELFSymbolVersionDefinition(
                    version=version_name,
                    version_index=(version_index),
                    flags=flags,
                    base=bool(flags & 0x1),
                    weak=bool(flags & 0x2),
                )

                definitions.append(definition)

                if version_index > 1:
                    index_map[version_index] = version_name

            except Exception:
                malformed += 1

    except Exception:
        malformed += 1

    return (
        tuple(definitions),
        index_map,
        malformed,
    )


def _extract_bindings(
    *,
    versym: GNUVerSymSection | None,
    dynsym: SymbolTableSection | None,
    requirement_map: dict[int, tuple[str, str]],
    definition_map: dict[int, str],
) -> tuple[
    tuple[ELFSymbolVersionBinding, ...],
    int,
]:
    """Map dynamic symbols to GNU version indexes."""
    if versym is None or dynsym is None:
        return (
            (),
            0,
        )

    bindings: list[ELFSymbolVersionBinding] = []

    malformed = 0

    try:
        symbols = list(dynsym.iter_symbols())

        for index, symbol in enumerate(symbols):
            try:
                if index >= versym.num_symbols():
                    break

                version_symbol = versym.get_symbol(index)

                entry = getattr(
                    version_symbol,
                    "entry",
                    None,
                )

                raw_index = _safe_int(
                    getattr(
                        entry,
                        "ndx",
                        0,
                    )
                )

                hidden = bool(raw_index & 0x8000)

                version_index = raw_index & 0x7FFF

                if version_index <= 1:
                    continue

                symbol_name = str(
                    getattr(
                        symbol,
                        "name",
                        "",
                    )
                    or ""
                ).strip()

                if not symbol_name:
                    continue

                symbol_entry = getattr(
                    symbol,
                    "entry",
                    None,
                )

                section_index = getattr(
                    symbol_entry,
                    "st_shndx",
                    None,
                )

                imported = str(section_index) == "SHN_UNDEF"

                exported = not imported

                version_name: str | None = None

                if version_index in requirement_map:
                    _, version_name = requirement_map[version_index]
                elif version_index in definition_map:
                    version_name = definition_map[version_index]

                bindings.append(
                    ELFSymbolVersionBinding(
                        symbol=symbol_name,
                        version=version_name,
                        version_index=(version_index),
                        imported=imported,
                        exported=exported,
                        hidden=hidden,
                    )
                )

            except Exception:
                malformed += 1

    except Exception:
        malformed += 1

    return (
        tuple(bindings),
        malformed,
    )


def _build_data(
    elf: ELFFile,
) -> ELFVersioningAnalysisData:
    """Build complete GNU symbol-versioning data."""
    versym_raw = elf.get_section_by_name(".gnu.version")

    verneed_raw = elf.get_section_by_name(".gnu.version_r")

    verdef_raw = elf.get_section_by_name(".gnu.version_d")

    dynsym_raw = elf.get_section_by_name(".dynsym")

    versym = (
        versym_raw
        if isinstance(
            versym_raw,
            GNUVerSymSection,
        )
        else None
    )

    verneed = (
        verneed_raw
        if isinstance(
            verneed_raw,
            GNUVerNeedSection,
        )
        else None
    )

    verdef = (
        verdef_raw
        if isinstance(
            verdef_raw,
            GNUVerDefSection,
        )
        else None
    )

    dynsym = (
        dynsym_raw
        if isinstance(
            dynsym_raw,
            SymbolTableSection,
        )
        else None
    )

    (
        requirements,
        requirement_map,
        requirement_malformed,
    ) = _extract_requirements(verneed)

    (
        definitions,
        definition_map,
        definition_malformed,
    ) = _extract_definitions(verdef)

    (
        bindings,
        binding_malformed,
    ) = _extract_bindings(
        versym=versym,
        dynsym=dynsym,
        requirement_map=(requirement_map),
        definition_map=(definition_map),
    )

    required_libraries = {requirement.library for requirement in requirements}

    glibc_versions = {
        requirement.version
        for requirement in requirements
        if requirement.version.startswith("GLIBC_")
    }

    glibcxx_versions = {
        requirement.version
        for requirement in requirements
        if requirement.version.startswith("GLIBCXX_")
    }

    cxxabi_versions = {
        requirement.version
        for requirement in requirements
        if requirement.version.startswith("CXXABI_")
    }

    imported_bindings = sum(binding.imported for binding in bindings)

    exported_bindings = sum(binding.exported for binding in bindings)

    versioning_present = bool(versym or verneed or verdef)

    return ELFVersioningAnalysisData(
        versioning_present=(versioning_present),
        versym_present=(versym is not None),
        verneed_present=(verneed is not None),
        verdef_present=(verdef is not None),
        required_library_count=len(required_libraries),
        required_version_count=len(requirements),
        defined_version_count=len(definitions),
        versioned_symbol_count=len(bindings),
        imported_versioned_symbol_count=(imported_bindings),
        exported_versioned_symbol_count=(exported_bindings),
        glibc_version_count=len(glibc_versions),
        glibcxx_version_count=len(glibcxx_versions),
        cxxabi_version_count=len(cxxabi_versions),
        highest_glibc_version=(_highest_version(glibc_versions)),
        highest_glibcxx_version=(_highest_version(glibcxx_versions)),
        highest_cxxabi_version=(_highest_version(cxxabi_versions)),
        malformed_entry_count=(requirement_malformed + definition_malformed + binding_malformed),
        requirements=requirements,
        definitions=definitions,
        bindings=bindings,
    )


def _build_findings(
    data: ELFVersioningAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative symbol-versioning findings."""
    findings: list[Finding] = []

    if data.malformed_entry_count > 0:
        findings.append(
            Finding(
                title=("Malformed ELF symbol-versioning metadata detected"),
                description=(
                    "One or more GNU symbol-versioning entries "
                    "could not be parsed or normalized cleanly."
                ),
                category="elf-versioning",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=(
                    Evidence(
                        kind=("elf-versioning"),
                        value=str(data.malformed_entry_count),
                        location=("GNU version sections"),
                    ),
                ),
                tags=(
                    "elf",
                    "symbol-versioning",
                    "malformed",
                ),
            )
        )

    return tuple(findings)


class ELFVersioningAnalyzer:
    """Analyze ELF GNU symbol versioning and ABI dependencies."""

    name = "elfversioning"
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
        """Analyze GNU symbol-versioning metadata."""
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
