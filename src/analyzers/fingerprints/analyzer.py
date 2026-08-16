"""PE fingerprint and import-hash analysis for Astra."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    FingerprintAnalysisData,
    FingerprintImport,
    FingerprintLibrary,
)


def _decode_bytes(
    value: bytes | None,
) -> str | None:
    """Decode PE-provided bytes safely."""
    if value is None:
        return None

    decoded = value.decode(
        "utf-8",
        errors="replace",
    ).strip()

    return decoded or None


def _normalize_library_name(
    library: str,
) -> str:
    """Normalize an imported library name for fingerprinting."""
    normalized = library.casefold().strip()

    for suffix in (
        ".dll",
        ".sys",
        ".ocx",
    ):
        if normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break

    return normalized


def _normalize_symbol(
    *,
    library: str,
    symbol: str | None,
    ordinal: int | None,
) -> str:
    """Build one normalized import fingerprint token."""
    normalized_library = _normalize_library_name(library)

    if symbol:
        return f"{normalized_library}.{symbol.casefold().strip()}"

    if ordinal is not None:
        return f"{normalized_library}.ord{ordinal}"

    return f"{normalized_library}.unknown"


def _normalize_import(
    *,
    library: str,
    imported: object,
) -> tuple[FingerprintImport, bool]:
    """Normalize one PE import entry.

    Returns the normalized entry plus whether the original record
    should be considered malformed.
    """
    name_value = getattr(
        imported,
        "name",
        None,
    )

    symbol = (
        _decode_bytes(name_value)
        if isinstance(name_value, bytes)
        else (str(name_value) if name_value is not None else None)
    )

    ordinal_value = getattr(
        imported,
        "ordinal",
        None,
    )

    ordinal = int(ordinal_value) if isinstance(ordinal_value, int) else None

    imported_by_name = symbol is not None
    imported_by_ordinal = not imported_by_name and ordinal is not None

    malformed = not imported_by_name and not imported_by_ordinal

    normalized = _normalize_symbol(
        library=library,
        symbol=symbol,
        ordinal=ordinal,
    )

    return (
        FingerprintImport(
            library=library,
            symbol=symbol,
            ordinal=ordinal,
            imported_by_name=(imported_by_name),
            imported_by_ordinal=(imported_by_ordinal),
            normalized=normalized,
        ),
        malformed,
    )


def _extract_libraries(
    pe: pefile.PE,
) -> tuple[
    tuple[FingerprintLibrary, ...],
    int,
]:
    """Extract normalized PE import libraries.

    Returns normalized libraries and malformed import count.
    """
    descriptors = getattr(
        pe,
        "DIRECTORY_ENTRY_IMPORT",
        (),
    )

    libraries: list[FingerprintLibrary] = []

    malformed_import_count = 0

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

        imports: list[FingerprintImport] = []

        for imported in getattr(
            descriptor,
            "imports",
            (),
        ):
            normalized_import, malformed = _normalize_import(
                library=library,
                imported=imported,
            )

            imports.append(normalized_import)

            if malformed:
                malformed_import_count += 1

        libraries.append(
            FingerprintLibrary(
                name=library,
                import_count=len(imports),
                named_import_count=sum(entry.imported_by_name for entry in imports),
                ordinal_import_count=sum(entry.imported_by_ordinal for entry in imports),
                imports=tuple(imports),
            )
        )

    return (
        tuple(libraries),
        malformed_import_count,
    )


def _fingerprint_source(
    libraries: tuple[FingerprintLibrary, ...],
) -> str | None:
    """Build deterministic normalized import fingerprint input."""
    entries = tuple(imported.normalized for library in libraries for imported in library.imports)

    if not entries:
        return None

    return ",".join(entries)


def _fallback_imphash(
    fingerprint_source: str | None,
) -> str | None:
    """Generate deterministic MD5 import hash fallback."""
    if not fingerprint_source:
        return None

    return hashlib.md5(
        fingerprint_source.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()


def _pefile_imphash(
    pe: pefile.PE,
) -> str | None:
    """Return pefile's canonical ImpHash when available."""
    try:
        value = pe.get_imphash()
    except Exception:
        return None

    if not value:
        return None

    return str(value).strip() or None


def _extract_data(
    pe: pefile.PE,
) -> FingerprintAnalysisData:
    """Extract normalized PE fingerprint information."""
    libraries, malformed_count = _extract_libraries(pe)

    source = _fingerprint_source(libraries)

    imphash = _pefile_imphash(pe)

    if imphash is None:
        imphash = _fallback_imphash(source)

    import_count = sum(library.import_count for library in libraries)

    named_import_count = sum(library.named_import_count for library in libraries)

    ordinal_import_count = sum(library.ordinal_import_count for library in libraries)

    return FingerprintAnalysisData(
        fingerprint_available=(imphash is not None or source is not None),
        imphash=imphash,
        import_library_count=len(libraries),
        import_count=(import_count),
        named_import_count=(named_import_count),
        ordinal_import_count=(ordinal_import_count),
        malformed_import_count=(malformed_count),
        fingerprint_source=(source),
        libraries=libraries,
    )


class FingerprintsAnalyzer:
    """Generate deterministic PE fingerprints."""

    name = "fingerprints"
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
        """Analyze PE imports and generate fingerprints."""
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
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )

                analysis_data = _extract_data(pe)
            finally:
                pe.close()

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=(AnalysisStatus.COMPLETED),
                started_at=started_at,
                duration_ms=duration_ms,
                findings=(),
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
