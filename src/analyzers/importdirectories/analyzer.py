"""PE delay-import and bound-import analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    BoundImportEntry,
    DelayImportEntry,
    DelayImportLibrary,
    Evidence,
    Finding,
    ImportDirectoryAnalysisData,
    Severity,
)

SUSPICIOUS_DELAY_IMPORTS = {
    "virtualalloc",
    "virtualallocex",
    "virtualprotect",
    "virtualprotectex",
    "writeprocessmemory",
    "readprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "createprocessa",
    "createprocessw",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopenurla",
    "internetopenurlw",
    "wsastartup",
    "connect",
    "recv",
    "send",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "openprocess",
    "terminateprocess",
    "regsetvalueexa",
    "regsetvalueexw",
}


def _decode_bytes(
    value: bytes | None,
) -> str | None:
    """Decode a PE string safely."""
    if value is None:
        return None

    decoded = value.decode(
        "utf-8",
        errors="replace",
    ).strip()

    return decoded or None


def _is_suspicious_import(
    name: str | None,
) -> bool:
    """Return whether a delayed import is security-relevant."""
    if not name:
        return False

    return name.casefold() in SUSPICIOUS_DELAY_IMPORTS


def _normalize_delay_import(
    *,
    library: str,
    imported: object,
) -> DelayImportEntry:
    """Normalize one delayed import symbol."""
    name_value = getattr(
        imported,
        "name",
        None,
    )

    name = (
        _decode_bytes(name_value)
        if isinstance(name_value, bytes)
        else (str(name_value) if name_value is not None else None)
    )

    ordinal_value = getattr(
        imported,
        "ordinal",
        None,
    )

    ordinal = int(ordinal_value) if ordinal_value is not None else None

    address = int(
        getattr(
            imported,
            "address",
            0,
        )
    )

    imported_by_name = name is not None
    imported_by_ordinal = not imported_by_name and ordinal is not None

    return DelayImportEntry(
        library=library,
        name=name,
        ordinal=ordinal,
        address=address,
        imported_by_name=imported_by_name,
        imported_by_ordinal=imported_by_ordinal,
        suspicious=_is_suspicious_import(name),
    )


def _extract_delay_imports(
    pe: pefile.PE,
) -> tuple[DelayImportLibrary, ...]:
    """Extract normalized delayed imports."""
    descriptors = getattr(
        pe,
        "DIRECTORY_ENTRY_DELAY_IMPORT",
        (),
    )

    libraries: list[DelayImportLibrary] = []

    for descriptor in descriptors:
        dll_value = getattr(
            descriptor,
            "dll",
            None,
        )

        library = (
            _decode_bytes(dll_value)
            if isinstance(dll_value, bytes)
            else (str(dll_value) if dll_value is not None else None)
        )

        if not library:
            library = "unknown"

        imports = tuple(
            _normalize_delay_import(
                library=library,
                imported=imported,
            )
            for imported in getattr(
                descriptor,
                "imports",
                (),
            )
        )

        libraries.append(
            DelayImportLibrary(
                library=library,
                import_count=len(imports),
                suspicious_import_count=sum(entry.suspicious for entry in imports),
                imports=imports,
            )
        )

    return tuple(libraries)


def _normalize_bound_import(
    descriptor: object,
) -> BoundImportEntry:
    """Normalize one bound-import descriptor."""
    name_value = getattr(
        descriptor,
        "name",
        None,
    )

    library = (
        _decode_bytes(name_value)
        if isinstance(name_value, bytes)
        else (str(name_value) if name_value is not None else "unknown")
    )
    if not library:
        library = "unknown"

    structure = getattr(
        descriptor,
        "struct",
        None,
    )

    timestamp = 0
    forwarder_count = 0
    malformed = structure is None

    if structure is not None:
        timestamp = int(
            getattr(
                structure,
                "TimeDateStamp",
                0,
            )
        )

        forwarder_count = int(
            getattr(
                structure,
                "NumberOfModuleForwarderRefs",
                0,
            )
        )

        if timestamp < 0 or forwarder_count < 0:
            malformed = True

    return BoundImportEntry(
        library=library,
        timestamp=max(
            0,
            timestamp,
        ),
        forwarder_count=max(
            0,
            forwarder_count,
        ),
        malformed=malformed,
    )


def _extract_bound_imports(
    pe: pefile.PE,
) -> tuple[BoundImportEntry, ...]:
    """Extract normalized PE bound-import descriptors."""
    descriptors = getattr(
        pe,
        "DIRECTORY_ENTRY_BOUND_IMPORT",
        (),
    )

    return tuple(_normalize_bound_import(descriptor) for descriptor in descriptors)


def _build_findings(
    data: ImportDirectoryAnalysisData,
) -> tuple[Finding, ...]:
    """Generate calibrated delay/bound import findings."""
    findings: list[Finding] = []

    suspicious_delay_imports = tuple(
        imported
        for library in data.delay_libraries
        for imported in library.imports
        if imported.suspicious
    )

    if suspicious_delay_imports:
        findings.append(
            Finding(
                title=("Suspicious delayed Windows API imports detected"),
                description=(
                    "One or more APIs imported through the PE delay-import "
                    "directory are commonly associated with process injection, "
                    "memory manipulation, execution, networking, persistence, "
                    "or anti-analysis behavior."
                ),
                category="delay-imports",
                severity=Severity.MEDIUM,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="delay-import",
                        value=(imported.name or f"ordinal:{imported.ordinal}"),
                        location=imported.library,
                        metadata={
                            "address": imported.address,
                        },
                    )
                    for imported in suspicious_delay_imports[:30]
                ),
                tags=(
                    "pe",
                    "delay-imports",
                    "windows-api",
                ),
            )
        )

    malformed_bound_imports = tuple(entry for entry in data.bound_imports if entry.malformed)

    if malformed_bound_imports:
        findings.append(
            Finding(
                title=("Malformed PE bound-import descriptors detected"),
                description=(
                    "One or more PE bound-import descriptors contain "
                    "missing or invalid structural metadata."
                ),
                category="bound-imports",
                severity=Severity.LOW,
                confidence=75,
                evidence=tuple(
                    Evidence(
                        kind="bound-import",
                        value=entry.library,
                        location="PE bound-import directory",
                        metadata={
                            "timestamp": entry.timestamp,
                            "forwarder_count": (entry.forwarder_count),
                        },
                    )
                    for entry in malformed_bound_imports[:20]
                ),
                tags=(
                    "pe",
                    "bound-imports",
                    "malformed",
                ),
            )
        )

    return tuple(findings)


def _extract_data(
    pe: pefile.PE,
) -> ImportDirectoryAnalysisData:
    """Extract normalized delay-import and bound-import data."""
    delay_libraries = _extract_delay_imports(pe)
    bound_imports = _extract_bound_imports(pe)

    delay_import_count = sum(library.import_count for library in delay_libraries)

    suspicious_delay_import_count = sum(
        library.suspicious_import_count for library in delay_libraries
    )

    malformed_bound_import_count = sum(entry.malformed for entry in bound_imports)

    return ImportDirectoryAnalysisData(
        delay_import_directory_present=bool(delay_libraries),
        bound_import_directory_present=bool(bound_imports),
        delay_library_count=len(delay_libraries),
        delay_import_count=(delay_import_count),
        suspicious_delay_import_count=(suspicious_delay_import_count),
        bound_library_count=len(bound_imports),
        malformed_bound_import_count=(malformed_bound_import_count),
        delay_libraries=delay_libraries,
        bound_imports=bound_imports,
    )


class ImportDirectoriesAnalyzer:
    """Analyze PE delay-import and bound-import directories."""

    name = "importdirectories"
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
        """Analyze PE delay-import and bound-import metadata."""
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
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"],
                    ]
                )

                analysis_data = _extract_data(pe)
            finally:
                pe.close()

            findings = _build_findings(analysis_data)

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
