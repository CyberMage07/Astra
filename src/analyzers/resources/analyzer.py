"""PE resource analysis for Astra."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    ResourceAnalysisData,
    ResourceEntry,
    ResourceType,
    Severity,
)


class _ResourceDataStructure(Protocol):
    """Required attributes of a PE resource data structure."""

    OffsetToData: int
    Size: int


class _ResourceDataEntry(Protocol):
    """Required attributes of a PE resource data entry."""

    struct: _ResourceDataStructure


HIGH_ENTROPY_THRESHOLD = 7.2
LARGE_RESOURCE_THRESHOLD = 5 * 1024 * 1024

RESOURCE_TYPE_MAP: dict[int, ResourceType] = {
    1: ResourceType.CURSOR,
    2: ResourceType.BITMAP,
    3: ResourceType.ICON,
    4: ResourceType.MENU,
    5: ResourceType.DIALOG,
    6: ResourceType.STRING,
    7: ResourceType.FONT_DIRECTORY,
    8: ResourceType.FONT,
    9: ResourceType.ACCELERATOR,
    10: ResourceType.RCDATA,
    11: ResourceType.MESSAGE_TABLE,
    12: ResourceType.GROUP_CURSOR,
    14: ResourceType.GROUP_ICON,
    16: ResourceType.VERSION,
    23: ResourceType.HTML,
    24: ResourceType.MANIFEST,
}

RESOURCE_TYPE_NAMES: dict[ResourceType, str] = {
    ResourceType.CURSOR: "CURSOR",
    ResourceType.BITMAP: "BITMAP",
    ResourceType.ICON: "ICON",
    ResourceType.MENU: "MENU",
    ResourceType.DIALOG: "DIALOG",
    ResourceType.STRING: "STRING",
    ResourceType.FONT_DIRECTORY: "FONTDIR",
    ResourceType.FONT: "FONT",
    ResourceType.ACCELERATOR: "ACCELERATOR",
    ResourceType.RCDATA: "RCDATA",
    ResourceType.MESSAGE_TABLE: "MESSAGE_TABLE",
    ResourceType.GROUP_CURSOR: "GROUP_CURSOR",
    ResourceType.GROUP_ICON: "GROUP_ICON",
    ResourceType.VERSION: "VERSION",
    ResourceType.HTML: "HTML",
    ResourceType.MANIFEST: "MANIFEST",
    ResourceType.UNKNOWN: "UNKNOWN",
}

LANGUAGE_NAMES: dict[int, str] = {
    0: "Neutral",
    9: "English",
    10: "Spanish",
    12: "French",
    7: "German",
    16: "Italian",
    17: "Japanese",
    18: "Korean",
    4: "Chinese",
    25: "Russian",
}


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for resource content."""
    if not data:
        return 0.0

    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    data_length = len(data)
    entropy = 0.0

    for count in frequencies:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


def _resource_type(
    identifier: int | None,
) -> ResourceType:
    """Map a numeric PE resource identifier to a normalized type."""
    if identifier is None:
        return ResourceType.UNKNOWN

    return RESOURCE_TYPE_MAP.get(
        identifier,
        ResourceType.UNKNOWN,
    )


def _entry_name(
    entry: object,
) -> str | None:
    """Return a resource directory entry name or numeric identifier."""
    name = getattr(entry, "name", None)

    if name is not None:
        return str(name)

    identifier = getattr(entry, "id", None)

    if identifier is None:
        return None

    return str(identifier)


def _entry_identifier(
    entry: object,
) -> int | None:
    """Return a numeric resource directory entry identifier."""
    identifier = getattr(entry, "id", None)

    if identifier is None:
        return None

    return int(identifier)


def _language_name(language_id: int | None) -> str | None:
    """Return a readable resource language label."""
    if language_id is None:
        return None

    primary_language = language_id & 0x3FF
    known_name = LANGUAGE_NAMES.get(primary_language)

    if known_name is not None:
        return known_name

    return f"Language {language_id}"


def _detect_embedded_file_type(
    data: bytes,
) -> tuple[str | None, bool]:
    """Detect common embedded file signatures."""
    if data.startswith(b"MZ"):
        return "pe", True

    if data.startswith(b"\x7fELF"):
        return "elf", True

    if data.startswith(b"PK\x03\x04"):
        return "zip", False

    if data.startswith(b"%PDF-"):
        return "pdf", False

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", False

    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", False

    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif", False

    if data.startswith(b"BM"):
        return "bitmap", False

    if data.startswith(b"{\\rtf"):
        return "rtf", False

    stripped = data.lstrip()

    if stripped.startswith(b"#!"):
        return "script", False

    if stripped.startswith(b"<html") or stripped.startswith(b"<!DOCTYPE html"):
        return "html", False

    return None, False


def _resource_data_entries(
    pe: pefile.PE,
) -> Iterator[
    tuple[
        object,
        object,
        object,
        ResourceType,
        str,
    ]
]:
    """Yield every leaf resource data entry from a PE resource tree."""
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)

    if root is None:
        return

    for type_entry in root.entries:
        type_identifier = _entry_identifier(type_entry)
        resource_type = _resource_type(type_identifier)

        type_name = _entry_name(type_entry) or RESOURCE_TYPE_NAMES[resource_type]

        type_directory = getattr(
            type_entry,
            "directory",
            None,
        )

        if type_directory is None:
            continue

        for name_entry in type_directory.entries:
            name_directory = getattr(
                name_entry,
                "directory",
                None,
            )

            if name_directory is None:
                continue

            for language_entry in name_directory.entries:
                data_entry = getattr(
                    language_entry,
                    "data",
                    None,
                )

                if data_entry is None:
                    continue

                yield (
                    name_entry,
                    language_entry,
                    data_entry,
                    resource_type,
                    type_name,
                )


def _extract_resource(
    pe: pefile.PE,
    name_entry: object,
    language_entry: object,
    data_entry: object,
    resource_type: ResourceType,
    type_name: str,
) -> ResourceEntry:
    """Extract and normalize one resource payload."""
    structure = cast(pefile.ResourceDataEntryData, data_entry).struct

    rva = int(structure.OffsetToData)
    size = int(structure.Size)
    offset = int(pe.get_offset_from_rva(rva))

    payload = pe.get_memory_mapped_image()[rva : rva + size]

    entropy = _calculate_entropy(payload)
    embedded_file_type, is_executable = _detect_embedded_file_type(payload)

    return ResourceEntry(
        resource_type=resource_type,
        type_name=type_name,
        name=_entry_name(name_entry),
        language=_language_name(_entry_identifier(language_entry)),
        rva=rva,
        offset=offset,
        size=size,
        entropy=entropy,
        sha256=hashlib.sha256(payload).hexdigest(),
        is_executable=is_executable,
        embedded_file_type=embedded_file_type,
        is_high_entropy=(entropy >= HIGH_ENTROPY_THRESHOLD),
    )


def _build_findings(
    resources: tuple[ResourceEntry, ...],
) -> tuple[Finding, ...]:
    """Create calibrated findings from resource properties."""
    findings: list[Finding] = []

    embedded_executables = tuple(resource for resource in resources if resource.is_executable)

    if embedded_executables:
        findings.append(
            Finding(
                title="Embedded executable resources detected",
                description=(
                    f"{len(embedded_executables)} PE resources "
                    "contain embedded PE or ELF executable data."
                ),
                category="pe-resource-payload",
                severity=Severity.HIGH,
                confidence=90,
                evidence=tuple(
                    Evidence(
                        kind="pe-resource",
                        value=(resource.name or resource.type_name),
                        location=(f"RVA 0x{resource.rva:x}"),
                        metadata={
                            "type": resource.resource_type.value,
                            "embedded_file_type": (resource.embedded_file_type),
                            "size": resource.size,
                            "sha256": resource.sha256,
                        },
                    )
                    for resource in embedded_executables[:20]
                ),
                tags=(
                    "pe",
                    "resource",
                    "embedded-payload",
                ),
                attack_techniques=("T1027.009",),
            )
        )

    suspicious_high_entropy = tuple(
        resource
        for resource in resources
        if (
            resource.is_high_entropy
            and resource.resource_type
            in {
                ResourceType.RCDATA,
                ResourceType.UNKNOWN,
                ResourceType.HTML,
            }
        )
    )

    if suspicious_high_entropy:
        findings.append(
            Finding(
                title="High-entropy embedded resources detected",
                description=(
                    f"{len(suspicious_high_entropy)} RCDATA, HTML, "
                    "or custom resources have high entropy and may "
                    "contain compressed or encrypted content."
                ),
                category="pe-resource-entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="pe-resource",
                        value=(resource.name or resource.type_name),
                        location=(f"RVA 0x{resource.rva:x}"),
                        metadata={
                            "entropy": resource.entropy,
                            "size": resource.size,
                            "sha256": resource.sha256,
                        },
                    )
                    for resource in suspicious_high_entropy[:20]
                ),
                tags=(
                    "pe",
                    "resource",
                    "entropy",
                    "packing",
                ),
                attack_techniques=("T1027",),
            )
        )

    large_suspicious_resources = tuple(
        resource
        for resource in resources
        if (
            resource.size >= LARGE_RESOURCE_THRESHOLD
            and resource.resource_type
            in {
                ResourceType.RCDATA,
                ResourceType.UNKNOWN,
                ResourceType.HTML,
            }
        )
    )

    if large_suspicious_resources:
        findings.append(
            Finding(
                title="Oversized custom resources detected",
                description=(
                    f"{len(large_suspicious_resources)} custom "
                    "resources are at least "
                    f"{LARGE_RESOURCE_THRESHOLD:,} bytes."
                ),
                category="pe-resource-size",
                severity=Severity.LOW,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="pe-resource",
                        value=(resource.name or resource.type_name),
                        location=(f"RVA 0x{resource.rva:x}"),
                        metadata={
                            "size": resource.size,
                            "sha256": resource.sha256,
                        },
                    )
                    for resource in large_suspicious_resources[:20]
                ),
                tags=(
                    "pe",
                    "resource",
                    "size",
                ),
            )
        )

    embedded_archives = tuple(
        resource for resource in resources if resource.embedded_file_type == "zip"
    )

    if embedded_archives:
        findings.append(
            Finding(
                title="Embedded archive resources detected",
                description=(
                    f"{len(embedded_archives)} resources contain embedded ZIP archive data."
                ),
                category="pe-resource-payload",
                severity=Severity.LOW,
                confidence=70,
                evidence=tuple(
                    Evidence(
                        kind="pe-resource",
                        value=(resource.name or resource.type_name),
                        location=(f"RVA 0x{resource.rva:x}"),
                        metadata={
                            "size": resource.size,
                            "sha256": resource.sha256,
                        },
                    )
                    for resource in embedded_archives[:20]
                ),
                tags=(
                    "pe",
                    "resource",
                    "archive",
                ),
            )
        )

    return tuple(findings)


class ResourcesAnalyzer:
    """Analyze PE resources and embedded payloads."""

    name = "resources"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Analyze PE resources and return normalized results."""
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
                resources = tuple(
                    _extract_resource(
                        pe,
                        name_entry,
                        language_entry,
                        data_entry,
                        resource_type,
                        type_name,
                    )
                    for (
                        name_entry,
                        language_entry,
                        data_entry,
                        resource_type,
                        type_name,
                    ) in _resource_data_entries(pe)
                )
            finally:
                pe.close()

            analysis_data = ResourceAnalysisData(
                resource_count=len(resources),
                resources=resources,
                icon_count=sum(
                    1
                    for resource in resources
                    if resource.resource_type
                    in {
                        ResourceType.ICON,
                        ResourceType.GROUP_ICON,
                    }
                ),
                manifest_count=sum(
                    1 for resource in resources if resource.resource_type is ResourceType.MANIFEST
                ),
                version_count=sum(
                    1 for resource in resources if resource.resource_type is ResourceType.VERSION
                ),
                rcdata_count=sum(
                    1 for resource in resources if resource.resource_type is ResourceType.RCDATA
                ),
                high_entropy_resources=sum(1 for resource in resources if resource.is_high_entropy),
                embedded_executables=sum(1 for resource in resources if resource.is_executable),
                embedded_archives=sum(
                    1 for resource in resources if resource.embedded_file_type == "zip"
                ),
                embedded_documents=sum(
                    1
                    for resource in resources
                    if resource.embedded_file_type
                    in {
                        "pdf",
                        "rtf",
                    }
                ),
                total_resource_bytes=sum(resource.size for resource in resources),
                largest_resource_size=max(
                    (resource.size for resource in resources),
                    default=0,
                ),
            )

            findings = _build_findings(resources)
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
