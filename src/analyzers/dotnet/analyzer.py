"""Managed .NET CLR and metadata analysis for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dnfile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    DotNetAnalysisData,
    DotNetAssemblyReference,
    DotNetStreamInfo,
    Evidence,
    Finding,
    Severity,
)

COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000
COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000

CLR_FLAG_NAMES: dict[int, str] = {
    COMIMAGE_FLAGS_ILONLY: "ILONLY",
    COMIMAGE_FLAGS_32BITREQUIRED: "32BITREQUIRED",
    COMIMAGE_FLAGS_IL_LIBRARY: "IL_LIBRARY",
    COMIMAGE_FLAGS_STRONGNAMESIGNED: "STRONGNAMESIGNED",
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: "NATIVE_ENTRYPOINT",
    COMIMAGE_FLAGS_TRACKDEBUGDATA: "TRACKDEBUGDATA",
    COMIMAGE_FLAGS_32BITPREFERRED: "32BITPREFERRED",
}


def _safe_int(
    value: object,
    default: int = 0,
) -> int:
    """Convert a parser-provided value to int safely."""
    if value is None:
        return default

    if isinstance(
        value,
        (
            int,
            str,
            bytes,
            bytearray,
        ),
    ):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    return default


def _safe_text(
    value: object,
) -> str | None:
    """Normalize a parser-provided text value."""
    if value is None:
        return None

    if isinstance(value, bytes):
        decoded = (
            value.decode(
                "utf-8",
                errors="replace",
            )
            .rstrip("\x00")
            .strip()
        )

        return decoded or None

    text = str(value).rstrip("\x00").strip()

    return text or None


def _rows(
    table: object | None,
) -> tuple[Any, ...]:
    """Return metadata-table rows safely."""
    if table is None:
        return ()

    raw_rows = getattr(
        table,
        "rows",
        (),
    )

    if raw_rows is None:
        return ()

    return tuple(raw_rows)


def _table(
    pe: dnfile.dnPE,
    name: str,
) -> object | None:
    """Return one .NET metadata table by attribute name."""
    net = getattr(
        pe,
        "net",
        None,
    )

    if net is None:
        return None

    tables = getattr(
        net,
        "mdtables",
        None,
    )

    if tables is None:
        return None

    return getattr(
        tables,
        name,
        None,
    )


def _clr_flag_names(
    flags: int,
) -> tuple[str, ...]:
    """Return readable CLR flag names."""
    return tuple(name for flag, name in CLR_FLAG_NAMES.items() if flags & flag)


def _metadata_streams(
    pe: dnfile.dnPE,
) -> tuple[DotNetStreamInfo, ...]:
    """Normalize .NET metadata streams."""
    net = getattr(
        pe,
        "net",
        None,
    )

    metadata = getattr(
        net,
        "metadata",
        None,
    )

    if metadata is None:
        return ()

    streams = getattr(
        metadata,
        "streams_list",
        (),
    )

    normalized: list[DotNetStreamInfo] = []

    for stream in streams or ():
        name = _safe_text(
            getattr(
                stream,
                "name",
                None,
            )
        )

        if name is None:
            name = "unknown"

        offset = _safe_int(
            getattr(
                stream,
                "file_offset",
                getattr(
                    stream,
                    "offset",
                    0,
                ),
            )
        )

        size = _safe_int(
            getattr(
                stream,
                "size",
                0,
            )
        )

        if size == 0:
            sizeof = getattr(
                stream,
                "sizeof",
                None,
            )

            if callable(sizeof):
                try:
                    size = _safe_int(sizeof())
                except Exception:
                    size = 0

        normalized.append(
            DotNetStreamInfo(
                name=name,
                offset=max(
                    0,
                    offset,
                ),
                size=max(
                    0,
                    size,
                ),
            )
        )

    return tuple(normalized)


def _assembly_info(
    pe: dnfile.dnPE,
) -> tuple[
    str | None,
    str | None,
    str | None,
]:
    """Extract primary assembly identity."""
    rows = _rows(
        _table(
            pe,
            "Assembly",
        )
    )

    if not rows:
        return None, None, None

    row = rows[0]

    name = _safe_text(
        getattr(
            row,
            "Name",
            None,
        )
    )

    culture = _safe_text(
        getattr(
            row,
            "Culture",
            None,
        )
    )

    major = _safe_int(
        getattr(
            row,
            "MajorVersion",
            0,
        )
    )
    minor = _safe_int(
        getattr(
            row,
            "MinorVersion",
            0,
        )
    )
    build = _safe_int(
        getattr(
            row,
            "BuildNumber",
            0,
        )
    )
    revision = _safe_int(
        getattr(
            row,
            "RevisionNumber",
            0,
        )
    )

    version = f"{major}.{minor}.{build}.{revision}"

    return (
        name,
        version,
        culture,
    )


def _module_name(
    pe: dnfile.dnPE,
) -> str | None:
    """Extract the primary managed module name."""
    rows = _rows(
        _table(
            pe,
            "Module",
        )
    )

    if not rows:
        return None

    return _safe_text(
        getattr(
            rows[0],
            "Name",
            None,
        )
    )


def _assembly_references(
    pe: dnfile.dnPE,
) -> tuple[DotNetAssemblyReference, ...]:
    """Normalize AssemblyRef metadata rows."""
    references: list[DotNetAssemblyReference] = []

    for row in _rows(
        _table(
            pe,
            "AssemblyRef",
        )
    ):
        name = _safe_text(
            getattr(
                row,
                "Name",
                None,
            )
        )

        if not name:
            name = "unknown"

        culture = _safe_text(
            getattr(
                row,
                "Culture",
                None,
            )
        )

        major = _safe_int(
            getattr(
                row,
                "MajorVersion",
                0,
            )
        )
        minor = _safe_int(
            getattr(
                row,
                "MinorVersion",
                0,
            )
        )
        build = _safe_int(
            getattr(
                row,
                "BuildNumber",
                0,
            )
        )
        revision = _safe_int(
            getattr(
                row,
                "RevisionNumber",
                0,
            )
        )

        references.append(
            DotNetAssemblyReference(
                name=name,
                major_version=major,
                minor_version=minor,
                build_number=build,
                revision_number=revision,
                culture=culture,
                version=(f"{major}.{minor}.{build}.{revision}"),
            )
        )

    return tuple(references)


def _metadata_version(
    pe: dnfile.dnPE,
) -> str | None:
    """Extract CLR metadata version string."""
    net = getattr(
        pe,
        "net",
        None,
    )

    metadata = getattr(
        net,
        "metadata",
        None,
    )

    if metadata is None:
        return None

    struct = getattr(
        metadata,
        "struct",
        None,
    )

    if struct is None:
        return None

    for field in (
        "Version",
        "VersionString",
    ):
        value = _safe_text(
            getattr(
                struct,
                field,
                None,
            )
        )

        if value:
            return value

    return _safe_text(
        getattr(
            metadata,
            "version",
            None,
        )
    )


def _runtime_version(
    pe: dnfile.dnPE,
) -> str | None:
    """Return the best available managed runtime version."""
    metadata_version = _metadata_version(pe)

    if metadata_version:
        return metadata_version

    net = getattr(
        pe,
        "net",
        None,
    )

    struct = getattr(
        net,
        "struct",
        None,
    )

    if struct is None:
        return None

    major = _safe_int(
        getattr(
            struct,
            "MajorRuntimeVersion",
            0,
        )
    )
    minor = _safe_int(
        getattr(
            struct,
            "MinorRuntimeVersion",
            0,
        )
    )

    if not major and not minor:
        return None

    return f"{major}.{minor}"


def _metadata_signature(
    pe: dnfile.dnPE,
) -> int | None:
    """Extract the metadata-root signature."""
    net = getattr(
        pe,
        "net",
        None,
    )

    metadata = getattr(
        net,
        "metadata",
        None,
    )

    struct = getattr(
        metadata,
        "struct",
        None,
    )

    if struct is None:
        return None

    signature = getattr(
        struct,
        "Signature",
        None,
    )

    if signature is None:
        return None

    return max(
        0,
        _safe_int(signature),
    )


def _pinvoke_count(
    pe: dnfile.dnPE,
) -> int:
    """Return the number of P/Invoke mapping rows."""
    return len(
        _rows(
            _table(
                pe,
                "ImplMap",
            )
        )
    )


def _extract_data(
    pe: dnfile.dnPE,
) -> DotNetAnalysisData:
    """Extract normalized managed CLR metadata."""
    net = getattr(
        pe,
        "net",
        None,
    )

    if net is None:
        return DotNetAnalysisData(
            dotnet_present=False,
        )

    clr_struct = getattr(
        net,
        "struct",
        None,
    )

    clr_header_present = clr_struct is not None

    metadata = getattr(
        net,
        "metadata",
        None,
    )
    metadata_present = metadata is not None

    flags = _safe_int(
        getattr(
            clr_struct,
            "Flags",
            0,
        )
    )

    native_entry_point = bool(flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)

    raw_entry_point = _safe_int(
        getattr(
            clr_struct,
            "EntryPointTokenOrRva",
            getattr(
                clr_struct,
                "EntryPointToken",
                0,
            ),
        )
    )

    entry_point_token: int | None = None
    entry_point_rva: int | None = None

    if raw_entry_point:
        if native_entry_point:
            entry_point_rva = raw_entry_point
        else:
            entry_point_token = raw_entry_point

    il_only = bool(flags & COMIMAGE_FLAGS_ILONLY)

    mixed_mode = clr_header_present and not il_only

    streams = _metadata_streams(pe)

    (
        assembly_name,
        assembly_version,
        assembly_culture,
    ) = _assembly_info(pe)

    references = _assembly_references(pe)

    type_definition_count = len(
        _rows(
            _table(
                pe,
                "TypeDef",
            )
        )
    )
    method_definition_count = len(
        _rows(
            _table(
                pe,
                "MethodDef",
            )
        )
    )
    member_reference_count = len(
        _rows(
            _table(
                pe,
                "MemberRef",
            )
        )
    )

    clr_header_size = _safe_int(
        getattr(
            clr_struct,
            "cb",
            getattr(
                clr_struct,
                "Cb",
                0,
            ),
        )
    )

    malformed_metadata = clr_header_present and not metadata_present

    return DotNetAnalysisData(
        dotnet_present=True,
        clr_header_present=(clr_header_present),
        metadata_present=(metadata_present),
        clr_header_size=max(
            0,
            clr_header_size,
        ),
        runtime_version=(_runtime_version(pe)),
        clr_flags=max(
            0,
            flags,
        ),
        clr_flag_names=(_clr_flag_names(flags)),
        il_only=il_only,
        thirty_two_bit_required=bool(flags & COMIMAGE_FLAGS_32BITREQUIRED),
        thirty_two_bit_preferred=bool(flags & COMIMAGE_FLAGS_32BITPREFERRED),
        strong_name_signed=bool(flags & COMIMAGE_FLAGS_STRONGNAMESIGNED),
        native_entry_point=(native_entry_point),
        mixed_mode=mixed_mode,
        entry_point_token=(entry_point_token),
        entry_point_rva=(entry_point_rva),
        metadata_signature=(_metadata_signature(pe)),
        metadata_version=(_metadata_version(pe)),
        stream_count=len(streams),
        streams=streams,
        assembly_name=(assembly_name),
        assembly_version=(assembly_version),
        assembly_culture=(assembly_culture),
        module_name=(_module_name(pe)),
        assembly_reference_count=(len(references)),
        assembly_references=(references),
        type_definition_count=(type_definition_count),
        method_definition_count=(method_definition_count),
        member_reference_count=(member_reference_count),
        pinvoke_method_count=(_pinvoke_count(pe)),
        malformed_metadata=(malformed_metadata),
    )


def _build_findings(
    data: DotNetAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative .NET metadata findings."""
    findings: list[Finding] = []

    if not data.dotnet_present:
        return ()

    if data.malformed_metadata:
        findings.append(
            Finding(
                title=("Malformed .NET metadata detected"),
                description=(
                    "A CLR header is present but the "
                    "managed metadata root could not be "
                    "parsed completely."
                ),
                category="dotnet-metadata",
                severity=Severity.MEDIUM,
                confidence=85,
                evidence=(
                    Evidence(
                        kind="dotnet-metadata",
                        value="malformed",
                        location="CLR metadata",
                    ),
                ),
                tags=(
                    "dotnet",
                    "clr",
                    "malformed",
                ),
            )
        )

    if data.mixed_mode:
        findings.append(
            Finding(
                title=("Mixed-mode .NET assembly detected"),
                description=(
                    "The managed PE contains a CLR "
                    "header but is not marked IL-only. "
                    "This may indicate a mixed managed/"
                    "native assembly and is contextual "
                    "rather than inherently malicious."
                ),
                category="dotnet-runtime",
                severity=Severity.INFO,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="clr-flags",
                        value=str(data.clr_flags),
                        location="CLR header",
                    ),
                ),
                tags=(
                    "dotnet",
                    "clr",
                    "mixed-mode",
                ),
            )
        )

    if data.pinvoke_method_count:
        findings.append(
            Finding(
                title=(".NET assembly uses native P/Invoke"),
                description=(
                    "The managed assembly contains "
                    "P/Invoke mappings to native APIs. "
                    "This is common in legitimate .NET "
                    "software and should be correlated "
                    "with the imported native functions."
                ),
                category="dotnet-interop",
                severity=Severity.INFO,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="pinvoke-count",
                        value=str(data.pinvoke_method_count),
                        location="ImplMap metadata table",
                    ),
                ),
                tags=(
                    "dotnet",
                    "pinvoke",
                    "interop",
                ),
            )
        )

    return tuple(findings)


class DotNetAnalyzer:
    """Analyze managed .NET CLR metadata embedded in PE files."""

    name = "dotnet"
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
        """Analyze CLR and managed metadata."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            pe = dnfile.dnPE(str(resolved_path))

            try:
                analysis_data = _extract_data(pe)
            finally:
                close = getattr(
                    pe,
                    "close",
                    None,
                )

                if callable(close):
                    close()

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

        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=(AnalysisStatus.PARTIAL),
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
