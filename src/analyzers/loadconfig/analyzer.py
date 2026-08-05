"""PE load-configuration and mitigation analysis for Astra."""

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
    LoadConfigAnalysisData,
    Severity,
)

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

GUARD_FLAG_NAMES: dict[int, str] = {
    0x00000100: "CF_INSTRUMENTED",
    0x00000200: "CFW_INSTRUMENTED",
    0x00000400: "CF_FUNCTION_TABLE_PRESENT",
    0x00000800: "SECURITY_COOKIE_UNUSED",
    0x00001000: "PROTECT_DELAYLOAD_IAT",
    0x00002000: "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
    0x00004000: "CF_EXPORT_SUPPRESSION_INFO_PRESENT",
    0x00008000: "CF_ENABLE_EXPORT_SUPPRESSION",
    0x00010000: "CF_LONGJUMP_TABLE_PRESENT",
    0x00020000: "RF_INSTRUMENTED",
    0x00040000: "RF_ENABLE",
    0x00080000: "RF_STRICT",
    0x00100000: "RETPOLINE_PRESENT",
    0x00200000: "EH_CONTINUATION_TABLE_PRESENT",
    0x00400000: "XFG_ENABLED",
    0x00800000: "CASTGUARD_PRESENT",
    0x01000000: "MEMCPY_PRESENT",
}

POINTER_FIELDS = (
    "SecurityCookie",
    "GuardCFCheckFunctionPointer",
    "GuardCFDispatchFunctionPointer",
    "GuardCFFunctionTable",
    "SEHandlerTable",
    "DynamicValueRelocTable",
)


def _optional_int(
    structure: object,
    field_name: str,
) -> int | None:
    """Return a nonzero integer structure field when present."""
    value = getattr(
        structure,
        field_name,
        None,
    )

    if value is None:
        return None

    normalized = int(value)

    if normalized == 0:
        return None

    return normalized


def _guard_flag_names(
    guard_flags: int,
) -> tuple[str, ...]:
    """Return normalized names for enabled GuardFlags bits."""
    return tuple(name for flag, name in sorted(GUARD_FLAG_NAMES.items()) if guard_flags & flag)


def _image_bounds(
    pe: pefile.PE,
) -> tuple[int, int]:
    """Return the loaded image virtual-address range."""
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

    return (
        image_base,
        image_base + size_of_image,
    )


def _pointer_is_valid(
    value: int | None,
    *,
    image_start: int,
    image_end: int,
) -> bool:
    """Return whether a load-config pointer falls inside the image."""
    if value is None:
        return True

    return image_start <= value < image_end


def _code_integrity_present(
    structure: object,
) -> bool:
    """Return whether code-integrity metadata is populated."""
    code_integrity = getattr(
        structure,
        "CodeIntegrity",
        None,
    )

    if code_integrity is None:
        return False

    fields = (
        "Flags",
        "Catalog",
        "CatalogOffset",
        "Reserved",
    )

    return any(
        int(
            getattr(
                code_integrity,
                field,
                0,
            )
        )
        != 0
        for field in fields
    )


def _extract_data(
    pe: pefile.PE,
) -> LoadConfigAnalysisData:
    """Extract normalized PE load-configuration data."""
    directory = getattr(
        pe,
        "DIRECTORY_ENTRY_LOAD_CONFIG",
        None,
    )

    if directory is None:
        return LoadConfigAnalysisData(
            load_config_present=False,
        )

    structure = getattr(
        directory,
        "struct",
        None,
    )

    if structure is None:
        return LoadConfigAnalysisData(
            load_config_present=True,
            malformed=True,
        )

    size = int(
        getattr(
            structure,
            "Size",
            0,
        )
    )
    timestamp = int(
        getattr(
            structure,
            "TimeDateStamp",
            0,
        )
    )
    major_version = int(
        getattr(
            structure,
            "MajorVersion",
            0,
        )
    )
    minor_version = int(
        getattr(
            structure,
            "MinorVersion",
            0,
        )
    )

    security_cookie = _optional_int(
        structure,
        "SecurityCookie",
    )
    guard_flags = int(
        getattr(
            structure,
            "GuardFlags",
            0,
        )
    )
    guard_cf_check_function = _optional_int(
        structure,
        "GuardCFCheckFunctionPointer",
    )
    guard_cf_dispatch_function = _optional_int(
        structure,
        "GuardCFDispatchFunctionPointer",
    )
    guard_cf_function_table = _optional_int(
        structure,
        "GuardCFFunctionTable",
    )
    guard_cf_function_count = int(
        getattr(
            structure,
            "GuardCFFunctionCount",
            0,
        )
    )

    seh_handler_table = _optional_int(
        structure,
        "SEHandlerTable",
    )
    seh_handler_count = int(
        getattr(
            structure,
            "SEHandlerCount",
            0,
        )
    )

    dynamic_value_reloc_table = _optional_int(
        structure,
        "DynamicValueRelocTable",
    )

    machine = int(pe.FILE_HEADER.Machine)

    safe_seh_applicable = machine == IMAGE_FILE_MACHINE_I386
    safe_seh_present = (
        safe_seh_applicable and seh_handler_table is not None and seh_handler_count > 0
    )

    dll_characteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    control_flow_guard_enabled = bool(
        dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF
        or guard_flags & (0x00000100 | 0x00000400)
    )

    image_start, image_end = _image_bounds(pe)

    pointer_values = tuple(
        value
        for value in (
            security_cookie,
            guard_cf_check_function,
            guard_cf_dispatch_function,
            guard_cf_function_table,
            seh_handler_table,
            dynamic_value_reloc_table,
        )
        if value is not None
    )

    invalid_pointer_count = sum(
        not _pointer_is_valid(
            value,
            image_start=image_start,
            image_end=image_end,
        )
        for value in pointer_values
    )

    malformed = size <= 0 or invalid_pointer_count > 0

    return LoadConfigAnalysisData(
        load_config_present=True,
        size=size,
        timestamp=timestamp,
        major_version=major_version,
        minor_version=minor_version,
        security_cookie=security_cookie,
        security_cookie_present=(security_cookie is not None),
        guard_flags=guard_flags,
        guard_flag_names=_guard_flag_names(guard_flags),
        control_flow_guard_enabled=(control_flow_guard_enabled),
        guard_cf_check_function=(guard_cf_check_function),
        guard_cf_dispatch_function=(guard_cf_dispatch_function),
        guard_cf_function_table=(guard_cf_function_table),
        guard_cf_function_count=(guard_cf_function_count),
        seh_handler_table=seh_handler_table,
        seh_handler_count=seh_handler_count,
        safe_seh_present=safe_seh_present,
        safe_seh_applicable=(safe_seh_applicable),
        dynamic_value_reloc_table=(dynamic_value_reloc_table),
        code_integrity_present=(_code_integrity_present(structure)),
        malformed=malformed,
        invalid_pointer_count=(invalid_pointer_count),
    )


def _build_findings(
    data: LoadConfigAnalysisData,
) -> tuple[Finding, ...]:
    """Generate calibrated findings from load-config metadata."""
    findings: list[Finding] = []

    if not data.load_config_present:
        return ()

    if data.malformed:
        findings.append(
            Finding(
                title=("Malformed PE load configuration detected"),
                description=(
                    "The PE load-configuration directory contains invalid size or pointer values."
                ),
                category="pe-load-config",
                severity=Severity.MEDIUM,
                confidence=85,
                evidence=(
                    Evidence(
                        kind="load-config",
                        value="malformed",
                        location="PE load configuration",
                        metadata={
                            "size": data.size,
                            "invalid_pointer_count": (data.invalid_pointer_count),
                        },
                    ),
                ),
                tags=(
                    "pe",
                    "load-config",
                    "malformed",
                ),
            )
        )

    if data.safe_seh_applicable and not data.safe_seh_present:
        findings.append(
            Finding(
                title="SafeSEH is not enabled",
                description=(
                    "This 32-bit PE does not expose a SafeSEH "
                    "handler table. This is a hardening observation, "
                    "not direct evidence of malicious behavior."
                ),
                category="binary-hardening",
                severity=Severity.INFO,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="load-config-mitigation",
                        value="SafeSEH disabled",
                        location="PE load configuration",
                    ),
                ),
                tags=(
                    "pe",
                    "load-config",
                    "safeseh",
                    "hardening",
                ),
            )
        )

    return tuple(findings)


class LoadConfigAnalyzer:
    """Analyze PE load configuration and binary mitigations."""

    name = "loadconfig"
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
        """Analyze PE load-configuration metadata."""
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
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
                )

                analysis_data = _extract_data(pe)
            finally:
                pe.close()

            findings = _build_findings(analysis_data)

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=(AnalysisStatus.COMPLETED),
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
