"""ELF symbol, import, and export analysis for Astra."""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ELFSymbolAnalysisData,
    ELFSymbolEntry,
    Evidence,
    Finding,
    Severity,
)

SHN_UNDEF = "SHN_UNDEF"

SUSPICIOUS_SYMBOLS: dict[
    str,
    tuple[
        str,
        Severity,
        int,
        str,
    ],
] = {
    "system": (
        "process-execution",
        Severity.MEDIUM,
        65,
        "Can execute commands through a shell.",
    ),
    "execve": (
        "process-execution",
        Severity.HIGH,
        80,
        "Can replace the current process with another executable.",
    ),
    "execl": (
        "process-execution",
        Severity.MEDIUM,
        65,
        "Can execute another program.",
    ),
    "execlp": (
        "process-execution",
        Severity.MEDIUM,
        65,
        "Can execute another program using PATH resolution.",
    ),
    "execv": (
        "process-execution",
        Severity.MEDIUM,
        65,
        "Can execute another program.",
    ),
    "execvp": (
        "process-execution",
        Severity.MEDIUM,
        65,
        "Can execute another program using PATH resolution.",
    ),
    "fork": (
        "process-control",
        Severity.LOW,
        45,
        "Can create a child process.",
    ),
    "vfork": (
        "process-control",
        Severity.LOW,
        45,
        "Can create a child process using shared address space semantics.",
    ),
    "clone": (
        "process-control",
        Severity.MEDIUM,
        60,
        "Can create processes or threads with fine-grained sharing controls.",
    ),
    "ptrace": (
        "anti-analysis",
        Severity.HIGH,
        85,
        "Can inspect or control another process and is commonly used for anti-debugging.",
    ),
    "mprotect": (
        "memory-protection",
        Severity.MEDIUM,
        70,
        "Can change memory page protections at runtime.",
    ),
    "mmap": (
        "memory-mapping",
        Severity.LOW,
        45,
        "Can create or modify memory mappings.",
    ),
    "dlopen": (
        "dynamic-loading",
        Severity.MEDIUM,
        65,
        "Can load shared objects dynamically at runtime.",
    ),
    "dlsym": (
        "dynamic-loading",
        Severity.MEDIUM,
        65,
        "Can resolve symbols dynamically at runtime.",
    ),
    "socket": (
        "network-access",
        Severity.LOW,
        45,
        "Can create network sockets.",
    ),
    "connect": (
        "network-access",
        Severity.MEDIUM,
        60,
        "Can establish outbound network connections.",
    ),
    "bind": (
        "network-access",
        Severity.MEDIUM,
        60,
        "Can bind a socket to a local address.",
    ),
    "listen": (
        "network-access",
        Severity.MEDIUM,
        60,
        "Can place a socket into listening mode.",
    ),
    "accept": (
        "network-access",
        Severity.MEDIUM,
        60,
        "Can accept inbound network connections.",
    ),
    "accept4": (
        "network-access",
        Severity.MEDIUM,
        60,
        "Can accept inbound network connections.",
    ),
    "setuid": (
        "privilege-control",
        Severity.HIGH,
        75,
        "Can change the process user identity.",
    ),
    "setgid": (
        "privilege-control",
        Severity.HIGH,
        75,
        "Can change the process group identity.",
    ),
    "chroot": (
        "environment-control",
        Severity.MEDIUM,
        55,
        "Can change the process root directory.",
    ),
    "unlink": (
        "file-manipulation",
        Severity.LOW,
        40,
        "Can delete filesystem entries.",
    ),
    "unlinkat": (
        "file-manipulation",
        Severity.LOW,
        40,
        "Can delete filesystem entries relative to a directory descriptor.",
    ),
}


def _load_elf(
    file_object: BinaryIO,
) -> ELFFile:
    """Construct an ELF parser."""
    return ELFFile(file_object)


def _normalize_section_index(
    value: object,
) -> str | int:
    """Normalize a symbol section index."""
    if isinstance(value, int):
        return value

    return str(value)


def _symbol_binding(
    symbol: object,
) -> str:
    """Return a normalized ELF symbol binding."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    info = getattr(
        entry,
        "st_info",
        None,
    )

    if info is None:
        return "UNKNOWN"

    bind = getattr(
        info,
        "bind",
        None,
    )

    if bind is None:
        try:
            bind = info["bind"]
        except Exception:
            return "UNKNOWN"

    return str(bind)


def _symbol_type(
    symbol: object,
) -> str:
    """Return a normalized ELF symbol type."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    info = getattr(
        entry,
        "st_info",
        None,
    )

    if info is None:
        return "UNKNOWN"

    symbol_type = getattr(
        info,
        "type",
        None,
    )

    if symbol_type is None:
        try:
            symbol_type = info["type"]
        except Exception:
            return "UNKNOWN"

    return str(symbol_type)


def _symbol_visibility(
    symbol: object,
) -> str:
    """Return normalized ELF symbol visibility."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    other = getattr(
        entry,
        "st_other",
        None,
    )

    if other is None:
        return "UNKNOWN"

    visibility = getattr(
        other,
        "visibility",
        None,
    )

    if visibility is None:
        try:
            visibility = other["visibility"]
        except Exception:
            return "UNKNOWN"

    return str(visibility)


def _symbol_value(
    symbol: object,
) -> int:
    """Return normalized symbol value."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    value = getattr(
        entry,
        "st_value",
        0,
    )

    return (
        int(value)
        if isinstance(
            value,
            int,
        )
        else 0
    )


def _symbol_size(
    symbol: object,
) -> int:
    """Return normalized symbol size."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    value = getattr(
        entry,
        "st_size",
        0,
    )

    return (
        int(value)
        if isinstance(
            value,
            int,
        )
        else 0
    )


def _symbol_section_index(
    symbol: object,
) -> str | int:
    """Return normalized symbol section index."""
    entry = getattr(
        symbol,
        "entry",
        None,
    )

    value = getattr(
        entry,
        "st_shndx",
        SHN_UNDEF,
    )

    return _normalize_section_index(value)


def _is_import(
    section_index: str | int,
) -> bool:
    """Return whether a symbol is undefined/imported."""
    return str(section_index) == SHN_UNDEF


def _is_export(
    *,
    section_index: str | int,
    binding: str,
    visibility: str,
) -> bool:
    """Return whether a symbol is externally visible and defined."""
    if _is_import(section_index):
        return False

    if binding not in {
        "STB_GLOBAL",
        "STB_WEAK",
    }:
        return False

    return visibility in {
        "STV_DEFAULT",
        "STV_PROTECTED",
    }


def _is_weak(
    binding: str,
) -> bool:
    """Return whether a symbol uses weak binding."""
    return binding == "STB_WEAK"


def _suspicious_metadata(
    name: str,
) -> tuple[
    bool,
    str | None,
]:
    """Return suspicious-symbol classification."""
    normalized = name.split("@", 1)[0].strip().casefold()

    metadata = SUSPICIOUS_SYMBOLS.get(normalized)

    if metadata is None:
        return (
            False,
            None,
        )

    return (
        True,
        metadata[0],
    )


def _normalize_symbol(
    symbol: object,
) -> ELFSymbolEntry | None:
    """Normalize one ELF symbol."""
    name = str(
        getattr(
            symbol,
            "name",
            "",
        )
    ).strip()

    if not name:
        return None

    binding = _symbol_binding(symbol)

    symbol_type = _symbol_type(symbol)

    visibility = _symbol_visibility(symbol)

    section_index = _symbol_section_index(symbol)

    imported = _is_import(section_index)

    exported = _is_export(
        section_index=section_index,
        binding=binding,
        visibility=visibility,
    )

    weak = _is_weak(binding)

    if imported:
        (
            suspicious,
            suspicious_category,
        ) = _suspicious_metadata(name)
    else:
        suspicious = False
        suspicious_category = None

    return ELFSymbolEntry(
        name=name,
        value=_symbol_value(symbol),
        size=_symbol_size(symbol),
        binding=binding,
        symbol_type=symbol_type,
        visibility=visibility,
        section_index=section_index,
        imported=imported,
        exported=exported,
        weak=weak,
        suspicious=suspicious,
        suspicious_category=(suspicious_category),
    )


def _extract_symbols(
    elf: ELFFile,
) -> tuple[
    tuple[ELFSymbolEntry, ...],
    int,
    int,
    int,
]:
    """Extract and normalize ELF symbol tables."""
    symbols: list[ELFSymbolEntry] = []

    dynamic_symbol_count = 0
    static_symbol_count = 0
    malformed_symbol_count = 0

    for section in elf.iter_sections():
        if not isinstance(
            section,
            SymbolTableSection,
        ):
            continue

        section_name = section.name or ""

        try:
            section_symbols = tuple(section.iter_symbols())

        except Exception:
            malformed_symbol_count += 1
            continue

        for symbol in section_symbols:
            try:
                normalized = _normalize_symbol(symbol)

                if normalized is None:
                    continue

                symbols.append(normalized)

                if section_name == ".dynsym":
                    dynamic_symbol_count += 1

                elif section_name == ".symtab":
                    static_symbol_count += 1

            except Exception:
                malformed_symbol_count += 1

    return (
        tuple(symbols),
        dynamic_symbol_count,
        static_symbol_count,
        malformed_symbol_count,
    )


def _is_stripped(
    elf: ELFFile,
) -> bool:
    """Return whether the traditional static symbol table is absent."""
    section = elf.get_section_by_name(".symtab")

    return not isinstance(
        section,
        SymbolTableSection,
    )


def _build_data(
    elf: ELFFile,
) -> ELFSymbolAnalysisData:
    """Build normalized ELF symbol-analysis data."""
    (
        symbols,
        dynamic_symbol_count,
        static_symbol_count,
        malformed_symbol_count,
    ) = _extract_symbols(elf)

    names = [symbol.name for symbol in symbols]

    duplicate_symbol_count = sum(count - 1 for count in Counter(names).values() if count > 1)

    return ELFSymbolAnalysisData(
        symbol_tables_present=bool(dynamic_symbol_count or static_symbol_count),
        symbol_count=len(symbols),
        dynamic_symbol_count=(dynamic_symbol_count),
        static_symbol_count=(static_symbol_count),
        import_count=sum(symbol.imported for symbol in symbols),
        export_count=sum(symbol.exported for symbol in symbols),
        weak_symbol_count=sum(symbol.weak for symbol in symbols),
        suspicious_symbol_count=sum(symbol.suspicious for symbol in symbols),
        duplicate_symbol_count=(duplicate_symbol_count),
        malformed_symbol_count=(malformed_symbol_count),
        stripped=_is_stripped(elf),
        symbols=symbols,
    )


def _build_findings(
    data: ELFSymbolAnalysisData,
) -> tuple[Finding, ...]:
    """Generate contextual findings from suspicious ELF symbols."""
    grouped: dict[
        str,
        list[ELFSymbolEntry],
    ] = {}

    for symbol in data.symbols:
        if not symbol.suspicious:
            continue

        category = symbol.suspicious_category or "unknown"

        grouped.setdefault(
            category,
            [],
        ).append(symbol)

    findings: list[Finding] = []

    category_metadata: dict[
        str,
        tuple[
            str,
            Severity,
            int,
        ],
    ] = {
        "anti-analysis": (
            "ELF anti-analysis capability",
            Severity.MEDIUM,
            80,
        ),
        "privilege-control": (
            "ELF privilege-control capability",
            Severity.MEDIUM,
            75,
        ),
        "process-execution": (
            "ELF process-execution capability",
            Severity.MEDIUM,
            70,
        ),
        "dynamic-loading": (
            "ELF runtime dynamic-loading capability",
            Severity.LOW,
            65,
        ),
        "memory-protection": (
            "ELF memory-protection manipulation capability",
            Severity.LOW,
            65,
        ),
        "network-access": (
            "ELF network-access capability",
            Severity.INFO,
            65,
        ),
        "process-control": (
            "ELF process-control capability",
            Severity.INFO,
            60,
        ),
        "memory-mapping": (
            "ELF memory-mapping capability",
            Severity.INFO,
            55,
        ),
        "file-manipulation": (
            "ELF file-manipulation capability",
            Severity.INFO,
            55,
        ),
        "environment-control": (
            "ELF environment-control capability",
            Severity.LOW,
            60,
        ),
    }

    for category, symbols in grouped.items():
        metadata = category_metadata.get(category)

        if metadata is None:
            continue

        (
            title,
            severity,
            confidence,
        ) = metadata

        findings.append(
            Finding(
                title=title,
                description=(
                    "The ELF binary imports symbols "
                    "associated with "
                    f"{category.replace('-', ' ')}. "
                    "These capabilities may be entirely "
                    "legitimate and should be interpreted "
                    "alongside other static and dynamic evidence."
                ),
                category=category,
                severity=severity,
                confidence=confidence,
                evidence=tuple(
                    Evidence(
                        kind="elf-symbol",
                        value=symbol.name,
                        location=".dynsym/.symtab",
                        metadata={
                            "binding": (symbol.binding),
                            "type": (symbol.symbol_type),
                            "visibility": (symbol.visibility),
                            "imported": (symbol.imported),
                            "exported": (symbol.exported),
                        },
                    )
                    for symbol in symbols[:20]
                ),
                tags=(
                    "elf",
                    "symbols",
                    category,
                ),
            )
        )

    return tuple(findings)


class ELFSymbolsAnalyzer:
    """Analyze ELF symbols, imports, and exports."""

    name = "elfsymbols"
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
        """Analyze ELF symbol tables."""
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
