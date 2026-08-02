"""Normalized metadata extraction for Astra samples."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    MetadataAnalysisData,
    MetadataEntry,
    MetadataSource,
    Severity,
)

FUTURE_TIMESTAMP_TOLERANCE_SECONDS = 24 * 60 * 60
EARLIEST_REASONABLE_TIMESTAMP = 315532800

VERSION_FIELD_MAP: dict[str, str] = {
    "CompanyName": "company_name",
    "ProductName": "product_name",
    "FileDescription": "file_description",
    "OriginalFilename": "original_filename",
    "InternalName": "internal_name",
    "ProductVersion": "product_version",
    "FileVersion": "file_version",
    "LegalCopyright": "legal_copyright",
}


def _decode_metadata_value(value: object) -> str:
    """Decode a PE metadata value safely."""
    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        ).strip("\x00 ")

    return str(value).strip("\x00 ")


def _extract_version_entries(
    pe: pefile.PE,
) -> tuple[MetadataEntry, ...]:
    """Extract normalized PE version information."""
    entries: list[MetadataEntry] = []

    for file_info_group in getattr(pe, "FileInfo", ()):
        for file_info in file_info_group:
            if getattr(file_info, "Key", b"") != b"StringFileInfo":
                continue

            for string_table in getattr(file_info, "StringTable", ()):
                for raw_key, raw_value in string_table.entries.items():
                    key = _decode_metadata_value(raw_key)
                    value = _decode_metadata_value(raw_value)

                    if not key or not value:
                        continue

                    entries.append(
                        MetadataEntry(
                            key=key,
                            value=value,
                            source=MetadataSource.PE_VERSION_INFO,
                            confidence=100,
                        )
                    )

    return tuple(entries)


def _extract_language(
    pe: pefile.PE,
) -> str | None:
    """Extract the first available PE translation language."""
    for file_info_group in getattr(pe, "FileInfo", ()):
        for file_info in file_info_group:
            if getattr(file_info, "Key", b"") != b"VarFileInfo":
                continue

            for variable in getattr(file_info, "Var", ()):
                entry = getattr(variable, "entry", {})
                translations = entry.get(
                    b"Translation",
                    entry.get("Translation", ()),
                )

                if not translations:
                    continue

                if isinstance(translations, dict):
                    translation_values = tuple(translations.values())
                elif isinstance(translations, (list, tuple)):
                    translation_values = tuple(translations)
                else:
                    translation_values = (translations,)

                flattened: list[int] = []

                for value in translation_values:
                    if isinstance(value, (list, tuple)):
                        flattened.extend(int(item) for item in value if isinstance(item, int))
                    elif isinstance(value, int):
                        flattened.append(value)

                if len(flattened) >= 2:
                    language_id = flattened[0]
                    code_page = flattened[1]

                    return f"language=0x{language_id:04x}, codepage={code_page}"

                if len(flattened) == 1:
                    combined = flattened[0]
                    language_id = combined & 0xFFFF
                    code_page = combined >> 16

                    return f"language=0x{language_id:04x}, codepage={code_page}"

    return None


def _entries_by_key(
    entries: tuple[MetadataEntry, ...],
) -> dict[str, str]:
    """Build a first-value lookup for metadata entries."""
    values: dict[str, str] = {}

    for entry in entries:
        values.setdefault(entry.key, entry.value)

    return values


def _compile_datetime(
    timestamp: int,
) -> datetime | None:
    """Convert a PE timestamp into UTC when valid."""
    try:
        return datetime.fromtimestamp(timestamp, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _timestamp_flags(
    timestamp: int,
    compile_datetime: datetime | None,
) -> tuple[bool, bool]:
    """Classify suspicious and future PE timestamps."""
    suspicious_timestamp = timestamp < EARLIEST_REASONABLE_TIMESTAMP or compile_datetime is None

    future_timestamp = (
        compile_datetime is not None
        and compile_datetime.timestamp()
        > datetime.now(UTC).timestamp() + FUTURE_TIMESTAMP_TOLERANCE_SECONDS
    )

    return suspicious_timestamp, future_timestamp


def _build_findings(
    data: MetadataAnalysisData,
) -> tuple[Finding, ...]:
    """Generate concise findings from metadata anomalies."""
    findings: list[Finding] = []

    if data.future_timestamp:
        findings.append(
            Finding(
                title="PE compile timestamp is in the future",
                description=(
                    "The executable compile timestamp is later than the "
                    "current time, which may indicate timestamp tampering."
                ),
                category="metadata",
                severity=Severity.MEDIUM,
                confidence=85,
                evidence=(
                    Evidence(
                        kind="compile-timestamp",
                        value=str(data.compile_timestamp),
                        location="PE file header",
                    ),
                ),
                tags=("pe", "metadata", "timestamp"),
                attack_techniques=("T1070.006",),
            )
        )
    elif data.suspicious_timestamp:
        findings.append(
            Finding(
                title="PE compile timestamp is suspicious",
                description=(
                    "The executable compile timestamp is invalid or predates "
                    "the modern Windows software era."
                ),
                category="metadata",
                severity=Severity.LOW,
                confidence=65,
                evidence=(
                    Evidence(
                        kind="compile-timestamp",
                        value=str(data.compile_timestamp),
                        location="PE file header",
                    ),
                ),
                tags=("pe", "metadata", "timestamp"),
            )
        )

    if not data.has_version_info:
        findings.append(
            Finding(
                title="PE version information is missing",
                description=(
                    "The executable does not contain normalized version "
                    "metadata such as company, product, or file description."
                ),
                category="metadata",
                severity=Severity.INFO,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="version-info",
                        value="missing",
                        location="PE resources",
                    ),
                ),
                tags=("pe", "metadata"),
            )
        )

    return tuple(findings)


class MetadataAnalyzer:
    """Extract normalized metadata from PE samples."""

    name = "metadata"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Extract normalized PE metadata."""
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
                pe.parse_data_directories()
                entries = _extract_version_entries(pe)
                values = _entries_by_key(entries)

                timestamp = int(pe.FILE_HEADER.TimeDateStamp)
                compile_datetime = _compile_datetime(timestamp)
                suspicious_timestamp, future_timestamp = _timestamp_flags(
                    timestamp,
                    compile_datetime,
                )

                language = _extract_language(pe)

                header_entries = (
                    MetadataEntry(
                        key="CompileTimestamp",
                        value=str(timestamp),
                        source=MetadataSource.PE_HEADER,
                        confidence=100,
                    ),
                )

                all_entries = (
                    *entries,
                    *header_entries,
                )

                analysis_data = MetadataAnalysisData(
                    entries=all_entries,
                    entry_count=len(all_entries),
                    company_name=values.get("CompanyName"),
                    product_name=values.get("ProductName"),
                    file_description=values.get("FileDescription"),
                    original_filename=values.get("OriginalFilename"),
                    internal_name=values.get("InternalName"),
                    product_version=values.get("ProductVersion"),
                    file_version=values.get("FileVersion"),
                    legal_copyright=values.get("LegalCopyright"),
                    language=language,
                    compile_timestamp=timestamp,
                    compile_datetime=compile_datetime,
                    has_version_info=bool(entries),
                    suspicious_timestamp=suspicious_timestamp,
                    future_timestamp=future_timestamp,
                )
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
                        error_type=type(error).__name__,
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
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
