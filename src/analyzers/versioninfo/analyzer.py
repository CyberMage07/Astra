"""PE version-information analysis for Astra."""

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
    Severity,
    VersionInfoAnalysisData,
    VersionStringEntry,
)

IDENTITY_FIELDS = (
    "CompanyName",
    "FileDescription",
    "OriginalFilename",
    "ProductName",
)

SUSPICIOUS_COMPANY_NAMES = {
    "microsoft",
    "microsoft corporation",
    "google",
    "google llc",
    "apple",
    "apple inc.",
    "adobe",
    "adobe systems",
    "oracle",
    "oracle corporation",
}

SUSPICIOUS_PRODUCT_NAMES = {
    "windows",
    "microsoft windows",
    "google chrome",
    "chrome",
    "adobe reader",
    "adobe acrobat",
    "java",
    "java runtime environment",
}


def _decode_value(
    value: object,
) -> str:
    """Return a normalized string value."""
    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        ).strip()

    return str(value).strip()


def _parse_translation(
    key: str,
) -> tuple[str | None, str | None]:
    """Split a version string-table key into language and code page."""
    normalized = key.strip()

    if len(normalized) != 8:
        return None, None

    language = normalized[:4]
    code_page = normalized[4:]

    return language, code_page


def _extract_string_file_info(
    pe: pefile.PE,
) -> tuple[VersionStringEntry, ...]:
    """Extract normalized StringFileInfo entries."""
    entries: list[VersionStringEntry] = []

    file_info = getattr(pe, "FileInfo", None)

    if not file_info:
        return ()

    for file_info_group in file_info:
        for info in file_info_group:
            key = _decode_value(getattr(info, "Key", ""))

            if key != "StringFileInfo":
                continue

            string_tables = getattr(
                info,
                "StringTable",
                (),
            )

            for string_table in string_tables:
                table_key = _decode_value(getattr(string_table, "LangID", ""))
                language, code_page = _parse_translation(table_key)

                entries_map = getattr(
                    string_table,
                    "entries",
                    {},
                )

                for raw_key, raw_value in entries_map.items():
                    normalized_key = _decode_value(raw_key)
                    normalized_value = _decode_value(raw_value)

                    if not normalized_key:
                        continue

                    entries.append(
                        VersionStringEntry(
                            key=normalized_key,
                            value=normalized_value,
                            language=language,
                            code_page=code_page,
                        )
                    )

    return tuple(entries)


def _extract_translation(
    pe: pefile.PE,
) -> tuple[str | None, str | None]:
    """Extract the first VarFileInfo translation."""
    file_info = getattr(pe, "FileInfo", None)

    if not file_info:
        return None, None

    for file_info_group in file_info:
        for info in file_info_group:
            key = _decode_value(getattr(info, "Key", ""))

            if key != "VarFileInfo":
                continue

            variables = getattr(
                info,
                "Var",
                (),
            )

            for variable in variables:
                entries = getattr(
                    variable,
                    "entry",
                    {},
                )

                for raw_key, raw_value in entries.items():
                    normalized_key = _decode_value(raw_key)

                    if normalized_key != "Translation":
                        continue

                    if isinstance(raw_value, dict):
                        for language, code_page in raw_value.items():
                            return (
                                f"{int(language):04X}",
                                f"{int(code_page):04X}",
                            )

                    if isinstance(
                        raw_value,
                        (list, tuple),
                    ):
                        values = tuple(raw_value)

                        if len(values) >= 2:
                            return (
                                f"{int(values[0]):04X}",
                                f"{int(values[1]):04X}",
                            )

    return None, None


def _field_value(
    entries: tuple[VersionStringEntry, ...],
    field_name: str,
) -> str | None:
    """Return the first non-empty value for a version field."""
    for entry in entries:
        if entry.key.casefold() == field_name.casefold() and entry.value:
            return entry.value

    return None


def _filename_matches(
    sample_name: str,
    original_filename: str | None,
) -> bool | None:
    """Compare the analyzed filename with OriginalFilename."""
    if original_filename is None:
        return None

    return Path(sample_name).name.casefold() == Path(original_filename).name.casefold()


def _is_suspicious_company_name(
    company_name: str | None,
) -> bool:
    """Return whether a company name impersonates a common vendor."""
    if not company_name:
        return False

    return company_name.casefold() in SUSPICIOUS_COMPANY_NAMES


def _is_suspicious_product_name(
    product_name: str | None,
) -> bool:
    """Return whether a product name impersonates common software."""
    if not product_name:
        return False

    return product_name.casefold() in SUSPICIOUS_PRODUCT_NAMES


def _missing_identity_fields(
    entries: tuple[VersionStringEntry, ...],
) -> bool:
    """Return whether important identity fields are missing."""
    present_keys = {entry.key.casefold() for entry in entries if entry.value}

    missing_count = sum(field.casefold() not in present_keys for field in IDENTITY_FIELDS)

    return missing_count >= 3


def _build_findings(
    data: VersionInfoAnalysisData,
    *,
    sample_name: str,
) -> tuple[Finding, ...]:
    """Generate calibrated findings from version information."""
    findings: list[Finding] = []

    if not data.version_info_present:
        return ()

    if data.original_filename_matches is False:
        findings.append(
            Finding(
                title="Original filename does not match analyzed file",
                description=(
                    "The PE version information reports an "
                    "OriginalFilename that differs from the actual "
                    "sample filename."
                ),
                category="pe-version-info",
                severity=Severity.LOW,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="version-info",
                        value=(data.original_filename or "unknown"),
                        location="OriginalFilename",
                        metadata={
                            "actual_filename": sample_name,
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "version-info",
                    "filename-mismatch",
                ),
            )
        )

    if data.suspicious_company_name:
        findings.append(
            Finding(
                title="Potential vendor impersonation in company metadata",
                description=(
                    "The PE claims a well-known company name. "
                    "This metadata should be correlated with the "
                    "digital signature and trust status."
                ),
                category="metadata-impersonation",
                severity=Severity.MEDIUM,
                confidence=65,
                evidence=(
                    Evidence(
                        kind="version-info",
                        value=(data.company_name or "unknown"),
                        location="CompanyName",
                    ),
                ),
                tags=(
                    "pe",
                    "version-info",
                    "impersonation",
                ),
                attack_techniques=("T1036",),
            )
        )

    if data.suspicious_product_name:
        findings.append(
            Finding(
                title="Potential software impersonation in product metadata",
                description=(
                    "The PE reports a product name associated with "
                    "widely deployed software. This may indicate "
                    "masquerading if other metadata is inconsistent."
                ),
                category="metadata-impersonation",
                severity=Severity.MEDIUM,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="version-info",
                        value=(data.product_name or "unknown"),
                        location="ProductName",
                    ),
                ),
                tags=(
                    "pe",
                    "version-info",
                    "masquerading",
                ),
                attack_techniques=("T1036",),
            )
        )

    if data.missing_identity_fields:
        findings.append(
            Finding(
                title="PE version identity metadata is incomplete",
                description=(
                    "Most expected identity fields are absent from the PE version information."
                ),
                category="pe-version-info",
                severity=Severity.INFO,
                confidence=60,
                evidence=(
                    Evidence(
                        kind="version-info",
                        value=str(data.string_count),
                        location="StringFileInfo",
                        metadata={
                            "expected_fields": (*IDENTITY_FIELDS,),
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "version-info",
                    "incomplete-metadata",
                ),
            )
        )

    return tuple(findings)


class VersionInfoAnalyzer:
    """Analyze PE StringFileInfo and VarFileInfo metadata."""

    name = "versioninfo"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze PE version-information resources."""
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
                entries = _extract_string_file_info(pe)
                language, code_page = _extract_translation(pe)
            finally:
                pe.close()

            version_info_present = bool(entries)

            company_name = _field_value(
                entries,
                "CompanyName",
            )
            file_description = _field_value(
                entries,
                "FileDescription",
            )
            file_version = _field_value(
                entries,
                "FileVersion",
            )
            internal_name = _field_value(
                entries,
                "InternalName",
            )
            legal_copyright = _field_value(
                entries,
                "LegalCopyright",
            )
            original_filename = _field_value(
                entries,
                "OriginalFilename",
            )
            product_name = _field_value(
                entries,
                "ProductName",
            )
            product_version = _field_value(
                entries,
                "ProductVersion",
            )

            if language is None and entries:
                language = entries[0].language

            if code_page is None and entries:
                code_page = entries[0].code_page

            analysis_data = VersionInfoAnalysisData(
                version_info_present=version_info_present,
                company_name=company_name,
                file_description=file_description,
                file_version=file_version,
                internal_name=internal_name,
                legal_copyright=legal_copyright,
                original_filename=original_filename,
                product_name=product_name,
                product_version=product_version,
                language=language,
                code_page=code_page,
                string_count=len(entries),
                strings=entries,
                original_filename_matches=_filename_matches(
                    resolved_path.name,
                    original_filename,
                ),
                suspicious_company_name=(_is_suspicious_company_name(company_name)),
                suspicious_product_name=(_is_suspicious_product_name(product_name)),
                missing_identity_fields=(
                    version_info_present and _missing_identity_fields(entries)
                ),
            )

            findings = _build_findings(
                analysis_data,
                sample_name=resolved_path.name,
            )

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
