"""ELF compiler, toolchain, runtime, and build provenance analysis for Astra."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFToolchainAnalysisData,
    ELFToolchainMarker,
)

_GCC_PATTERN = re.compile(
    r"\bGCC(?:\:?\s*\([^)]*\))?\s*([0-9]+(?:\.[0-9]+){1,3})?",
    re.IGNORECASE,
)

_CLANG_PATTERN = re.compile(
    r"\b(?:clang|LLVM clang)\s+version\s+([0-9]+(?:\.[0-9]+){1,3})",
    re.IGNORECASE,
)

_LLD_PATTERN = re.compile(
    r"\bLLD\s+([0-9]+(?:\.[0-9]+){1,3})",
    re.IGNORECASE,
)

_GNU_LD_PATTERN = re.compile(
    r"\bGNU ld\b.*?([0-9]+(?:\.[0-9]+){1,3})",
    re.IGNORECASE,
)

_RUST_PATTERN = re.compile(
    r"\brustc\b(?:\s+version)?\s*([0-9]+(?:\.[0-9]+){1,3})?",
    re.IGNORECASE,
)

_GO_PATTERN = re.compile(
    r"\bgo(?:1\.)?[0-9]+(?:\.[0-9]+){0,2}\b",
    re.IGNORECASE,
)

_PRINTABLE_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _safe_section_data(
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


def _decode_strings(
    data: bytes,
) -> tuple[str, ...]:
    """Extract printable ASCII strings from raw bytes."""
    values: list[str] = []

    for match in _PRINTABLE_PATTERN.finditer(data):
        value = (
            match.group()
            .decode(
                "utf-8",
                errors="ignore",
            )
            .strip()
        )

        if value:
            values.append(value)

    return tuple(values)


def _comment_entries(
    elf: ELFFile,
) -> tuple[
    tuple[str, ...],
    int,
]:
    """Extract strings from the ELF .comment section."""
    section = elf.get_section_by_name(".comment")

    if section is None:
        return (
            (),
            0,
        )

    try:
        data = _safe_section_data(section)

        if not data:
            return (
                (),
                0,
            )

        entries = tuple(
            value.strip()
            for value in data.decode(
                "utf-8",
                errors="ignore",
            ).split("\x00")
            if value.strip()
        )

        return (
            entries,
            0,
        )

    except Exception:
        return (
            (),
            1,
        )


def _build_id(
    elf: ELFFile,
) -> tuple[
    str | None,
    int,
]:
    """Extract GNU build-id from note sections."""
    malformed = 0

    for section in elf.iter_sections():
        if not isinstance(
            section,
            NoteSection,
        ):
            continue

        try:
            for note in section.iter_notes():
                try:
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

                    if not (
                        note_name == "GNU"
                        and note_type
                        in {
                            "NT_GNU_BUILD_ID",
                            "3",
                        }
                    ):
                        continue

                    descriptor = note.get("n_desc")

                    if isinstance(
                        descriptor,
                        str,
                    ):
                        return (
                            descriptor,
                            malformed,
                        )

                    if isinstance(
                        descriptor,
                        bytes,
                    ):
                        return (
                            descriptor.hex(),
                            malformed,
                        )

                except Exception:
                    malformed += 1

        except Exception:
            malformed += 1

    return (
        None,
        malformed,
    )


def _scan_binary_strings(
    sample_path: Path,
) -> tuple[str, ...]:
    """Extract candidate provenance strings from the full ELF file."""
    data = sample_path.read_bytes()

    return _decode_strings(data)


def _add_marker(
    markers: list[ELFToolchainMarker],
    *,
    category: str,
    value: str,
    source: str,
    confidence: int,
) -> None:
    """Append one marker while suppressing exact duplicates."""
    candidate = (
        category,
        value,
        source,
    )

    existing = {
        (
            marker.category,
            marker.value,
            marker.source,
        )
        for marker in markers
    }

    if candidate in existing:
        return

    markers.append(
        ELFToolchainMarker(
            category=category,
            value=value,
            source=source,
            confidence=confidence,
        )
    )


def _parse_comment_markers(
    entries: tuple[str, ...],
    markers: list[ELFToolchainMarker],
) -> tuple[
    bool,
    bool,
    str | None,
    str | None,
]:
    """Extract compiler information from .comment entries."""
    gcc_detected = False
    clang_detected = False

    compiler: str | None = None
    compiler_version: str | None = None

    for entry in entries:
        gcc_match = _GCC_PATTERN.search(entry)

        if gcc_match is not None:
            gcc_detected = True

            version = gcc_match.group(1) if gcc_match.lastindex else None

            _add_marker(
                markers,
                category="compiler",
                value=entry,
                source=".comment",
                confidence=95,
            )

            if compiler is None:
                compiler = "GCC"
                compiler_version = version

        clang_match = _CLANG_PATTERN.search(entry)

        if clang_match is not None:
            clang_detected = True

            version = clang_match.group(1)

            _add_marker(
                markers,
                category="compiler",
                value=entry,
                source=".comment",
                confidence=95,
            )

            if compiler is None:
                compiler = "Clang"
                compiler_version = version

    return (
        gcc_detected,
        clang_detected,
        compiler,
        compiler_version,
    )


def _parse_binary_markers(
    strings: tuple[str, ...],
    markers: list[ELFToolchainMarker],
) -> tuple[
    bool,
    bool,
    bool,
    bool,
    bool,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
]:
    """Extract compiler, linker, language, runtime, and LTO clues."""
    gcc_detected = False
    clang_detected = False
    rust_detected = False
    go_detected = False
    lto_detected = False

    compiler: str | None = None
    compiler_version: str | None = None

    linker: str | None = None
    linker_version: str | None = None

    language: str | None = None

    for value in strings:
        normalized = value.casefold()

        if "gcc:" in normalized or "gcc version" in normalized:
            gcc_match = _GCC_PATTERN.search(value)

            gcc_detected = True

            _add_marker(
                markers,
                category="compiler",
                value=value,
                source="binary-strings",
                confidence=70,
            )

            if compiler is None:
                compiler = "GCC"

                if gcc_match is not None:
                    compiler_version = gcc_match.group(1)

        clang_match = _CLANG_PATTERN.search(value)

        if clang_match is not None:
            clang_detected = True

            _add_marker(
                markers,
                category="compiler",
                value=value,
                source="binary-strings",
                confidence=75,
            )

            if compiler is None:
                compiler = "Clang"
                compiler_version = clang_match.group(1)

        rust_match = _RUST_PATTERN.search(value)

        if rust_match is not None:
            rust_detected = True
            language = language or "Rust"

            _add_marker(
                markers,
                category="language",
                value=value,
                source="binary-strings",
                confidence=80,
            )

        if (
            "rust_begin_unwind" in normalized
            or "rust_eh_personality" in normalized
            or "core::panicking" in normalized
        ):
            rust_detected = True
            language = language or "Rust"

            _add_marker(
                markers,
                category="language",
                value=value,
                source="binary-strings",
                confidence=85,
            )

        if (
            "go build id:" in normalized
            or "runtime.main" in normalized
            or "runtime.gopanic" in normalized
            or "go.buildid" in normalized
        ):
            go_detected = True
            language = language or "Go"

            _add_marker(
                markers,
                category="language",
                value=value,
                source="binary-strings",
                confidence=90,
            )

        elif _GO_PATTERN.search(value):
            go_detected = True

            _add_marker(
                markers,
                category="runtime",
                value=value,
                source="binary-strings",
                confidence=60,
            )

        lld_match = _LLD_PATTERN.search(value)

        if lld_match is not None:
            _add_marker(
                markers,
                category="linker",
                value=value,
                source="binary-strings",
                confidence=85,
            )

            if linker is None:
                linker = "LLD"
                linker_version = lld_match.group(1)

        gnu_ld_match = _GNU_LD_PATTERN.search(value)

        if gnu_ld_match is not None:
            _add_marker(
                markers,
                category="linker",
                value=value,
                source="binary-strings",
                confidence=85,
            )

            if linker is None:
                linker = "GNU ld"
                linker_version = gnu_ld_match.group(1)

        if (
            ".gnu.lto_" in normalized
            or "lto1" in normalized
            or "llvm.lto" in normalized
            or "thinlto" in normalized
        ):
            lto_detected = True

            _add_marker(
                markers,
                category="build",
                value=value,
                source="binary-strings",
                confidence=75,
            )

    return (
        gcc_detected,
        clang_detected,
        rust_detected,
        go_detected,
        lto_detected,
        compiler,
        compiler_version,
        linker,
        linker_version,
        language,
    )


def _runtime_from_markers(
    markers: tuple[ELFToolchainMarker, ...],
    *,
    rust_detected: bool,
    go_detected: bool,
) -> str | None:
    """Infer a coarse runtime label."""
    if go_detected:
        return "Go runtime"

    if rust_detected:
        return "Rust standard runtime"

    values = " ".join(marker.value.casefold() for marker in markers)

    if "libstdc++" in values:
        return "libstdc++"

    if "libgcc" in values:
        return "libgcc"

    return None


def _build_data(
    elf: ELFFile,
    *,
    sample_path: Path,
) -> ELFToolchainAnalysisData:
    """Build compiler and provenance analysis data."""
    (
        comment_entries,
        comment_malformed,
    ) = _comment_entries(elf)

    (
        build_id,
        note_malformed,
    ) = _build_id(elf)

    binary_strings = _scan_binary_strings(sample_path)

    markers: list[ELFToolchainMarker] = []

    (
        comment_gcc,
        comment_clang,
        comment_compiler,
        comment_compiler_version,
    ) = _parse_comment_markers(
        comment_entries,
        markers,
    )

    (
        binary_gcc,
        binary_clang,
        rust_detected,
        go_detected,
        lto_detected,
        binary_compiler,
        binary_compiler_version,
        linker,
        linker_version,
        language,
    ) = _parse_binary_markers(
        binary_strings,
        markers,
    )

    gcc_detected = bool(comment_gcc or binary_gcc)

    clang_detected = bool(comment_clang or binary_clang)

    primary_compiler = comment_compiler or binary_compiler

    compiler_version = comment_compiler_version or binary_compiler_version

    if build_id is not None:
        _add_marker(
            markers,
            category="build-id",
            value=build_id,
            source="GNU note",
            confidence=100,
        )

    marker_tuple = tuple(markers)

    runtime = _runtime_from_markers(
        marker_tuple,
        rust_detected=(rust_detected),
        go_detected=(go_detected),
    )

    compiler_marker_count = sum(marker.category == "compiler" for marker in marker_tuple)

    linker_marker_count = sum(marker.category == "linker" for marker in marker_tuple)

    runtime_marker_count = sum(marker.category == "runtime" for marker in marker_tuple)

    language_marker_count = sum(marker.category == "language" for marker in marker_tuple)

    toolchain_detected = bool(
        primary_compiler or linker or language or runtime or build_id or marker_tuple
    )

    return ELFToolchainAnalysisData(
        toolchain_detected=(toolchain_detected),
        primary_compiler=(primary_compiler),
        compiler_version=(compiler_version),
        linker=linker,
        linker_version=(linker_version),
        language=language,
        runtime=runtime,
        gcc_detected=(gcc_detected),
        clang_detected=(clang_detected),
        rust_detected=(rust_detected),
        go_detected=(go_detected),
        lto_detected=(lto_detected),
        comment_section_present=(bool(comment_entries)),
        comment_entry_count=len(comment_entries),
        build_id=build_id,
        compiler_marker_count=(compiler_marker_count),
        linker_marker_count=(linker_marker_count),
        runtime_marker_count=(runtime_marker_count),
        language_marker_count=(language_marker_count),
        malformed_entry_count=(comment_malformed + note_malformed),
        markers=marker_tuple,
    )


class ELFToolchainAnalyzer:
    """Analyze ELF compiler, toolchain, runtime, and build provenance."""

    name = "elftoolchain"
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
        """Analyze ELF compiler and build provenance."""
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

                analysis_data = _build_data(
                    elf,
                    sample_path=(resolved_path),
                )

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
