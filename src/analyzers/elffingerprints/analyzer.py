"""ELF fingerprint and clustering analysis for Astra."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFFingerprintAnalysisData,
    ELFFingerprintSource,
)


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _sha256_text(
    value: str,
) -> str:
    """Return SHA-256 of normalized text."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_symbol_name(
    name: str,
) -> str:
    """Normalize symbol names for fingerprinting."""
    return name.split("@", 1)[0].strip().casefold()


def _extract_imports(
    elf: ELFFile,
) -> tuple[str, ...]:
    """Extract deterministic imported symbol names."""
    names: set[str] = set()

    for section in elf.iter_sections():
        if not isinstance(
            section,
            SymbolTableSection,
        ):
            continue

        if section.name != ".dynsym":
            continue

        try:
            for symbol in section.iter_symbols():
                name = str(
                    getattr(
                        symbol,
                        "name",
                        "",
                    )
                ).strip()

                if not name:
                    continue

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

                if str(section_index) != "SHN_UNDEF":
                    continue

                normalized = _normalize_symbol_name(name)

                if normalized:
                    names.add(normalized)

        except Exception:
            continue

    return tuple(sorted(names))


def _extract_libraries(
    elf: ELFFile,
) -> tuple[str, ...]:
    """Extract deterministic DT_NEEDED library names."""
    libraries: set[str] = set()

    for section in elf.iter_sections():
        if not isinstance(
            section,
            DynamicSection,
        ):
            continue

        try:
            for tag in section.iter_tags():
                if str(tag.entry.d_tag) != "DT_NEEDED":
                    continue

                library = str(
                    getattr(
                        tag,
                        "needed",
                        "",
                    )
                ).strip()

                if library:
                    libraries.add(library.casefold())

        except Exception:
            continue

    return tuple(sorted(libraries))


def _extract_sections(
    elf: ELFFile,
) -> tuple[str, ...]:
    """Extract deterministic section-layout descriptors."""
    descriptors: list[str] = []

    for section in elf.iter_sections():
        try:
            name = section.name or "(unnamed)"

            header = section.header

            section_type = str(
                header.get(
                    "sh_type",
                    "unknown",
                )
            )

            flags = header.get(
                "sh_flags",
                0,
            )

            size = header.get(
                "sh_size",
                0,
            )

            if not isinstance(
                flags,
                int,
            ):
                flags = 0

            if not isinstance(
                size,
                int,
            ):
                size = 0

            descriptors.append(f"{name.casefold()}:{section_type}:{flags:x}:{size}")

        except Exception:
            continue

    return tuple(descriptors)


def _normalize_build_id(
    value: object,
) -> str | None:
    """Normalize a GNU Build-ID value."""
    if isinstance(
        value,
        bytes,
    ):
        return value.hex()

    if isinstance(
        value,
        str,
    ):
        normalized = value.strip().lower().removeprefix("0x")

        return normalized if normalized else None

    return None


def _extract_build_id(
    elf: ELFFile,
) -> str | None:
    """Extract GNU Build-ID from ELF notes."""
    for section in elf.iter_sections():
        if not isinstance(
            section,
            NoteSection,
        ):
            continue

        try:
            for note in section.iter_notes():
                note_type = str(
                    note.get(
                        "n_type",
                        "",
                    )
                )

                note_name = str(
                    note.get(
                        "n_name",
                        "",
                    )
                )

                if note_type != "NT_GNU_BUILD_ID" and note_name != "GNU":
                    continue

                build_id = _normalize_build_id(note.get("n_desc"))

                if build_id:
                    return build_id

        except Exception:
            continue

    return None


def _make_source(
    *,
    name: str,
    items: tuple[str, ...],
) -> ELFFingerprintSource | None:
    """Build one normalized fingerprint source."""
    if not items:
        return None

    normalized_source = ",".join(items)

    return ELFFingerprintSource(
        name=name,
        item_count=len(items),
        normalized_source=(normalized_source),
        sha256=_sha256_text(normalized_source),
    )


def _build_data(
    elf: ELFFile,
) -> ELFFingerprintAnalysisData:
    """Build normalized ELF fingerprints."""
    imports = _extract_imports(elf)

    libraries = _extract_libraries(elf)

    sections = _extract_sections(elf)

    build_id = _extract_build_id(elf)

    sources: list[ELFFingerprintSource] = []

    import_source = _make_source(
        name="imports",
        items=imports,
    )

    library_source = _make_source(
        name="libraries",
        items=libraries,
    )

    section_source = _make_source(
        name="sections",
        items=sections,
    )

    if import_source is not None:
        sources.append(import_source)

    if library_source is not None:
        sources.append(library_source)

    if section_source is not None:
        sources.append(section_source)

    combined_components = tuple(source.sha256 for source in sources)

    combined_source = "|".join(combined_components)

    combined_fingerprint = _sha256_text(combined_source) if combined_source else None

    return ELFFingerprintAnalysisData(
        fingerprint_available=bool(sources or build_id),
        import_fingerprint=(import_source.sha256 if import_source is not None else None),
        library_fingerprint=(library_source.sha256 if library_source is not None else None),
        section_fingerprint=(section_source.sha256 if section_source is not None else None),
        combined_fingerprint=(combined_fingerprint),
        build_id=build_id,
        imported_symbol_count=len(imports),
        needed_library_count=len(libraries),
        section_count=len(sections),
        source_count=len(sources),
        sources=tuple(sources),
    )


class ELFFingerprintsAnalyzer:
    """Generate deterministic ELF fingerprints."""

    name = "elffingerprints"
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
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Generate fingerprints for one ELF sample."""
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
