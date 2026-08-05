"""PE debug-directory and PDB metadata analysis for Astra."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    DebugAnalysisData,
    DebugDirectoryEntry,
    Evidence,
    Finding,
    Severity,
)

IMAGE_DEBUG_TYPE_NAMES: dict[int, str] = {
    0: "UNKNOWN",
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    7: "OMAP_TO_SRC",
    8: "OMAP_FROM_SRC",
    9: "BORLAND",
    10: "RESERVED10",
    11: "CLSID",
    12: "VC_FEATURE",
    13: "POGO",
    14: "ILTCG",
    15: "MPX",
    16: "REPRO",
    17: "EX_DLLCHARACTERISTICS",
}

CODEVIEW_TYPE = 2
REPRO_TYPE = 16

RSDS_SIGNATURE = b"RSDS"
NB10_SIGNATURE = b"NB10"

MAX_DEBUG_DATA_SIZE = 16 * 1024 * 1024
MAX_PDB_PATH_LENGTH = 4096


def _debug_type_name(
    debug_type: int,
) -> str:
    """Return a readable PE debug-directory type."""
    return IMAGE_DEBUG_TYPE_NAMES.get(
        debug_type,
        f"UNKNOWN_{debug_type}",
    )


def _decode_c_string(
    value: bytes,
) -> str | None:
    """Decode a null-terminated debug string safely."""
    raw_value = value.split(
        b"\x00",
        maxsplit=1,
    )[0]

    if not raw_value:
        return None

    decoded = raw_value.decode(
        "utf-8",
        errors="replace",
    ).strip()

    if not decoded:
        return None

    return decoded[:MAX_PDB_PATH_LENGTH]


def _read_debug_payload(
    sample_data: bytes,
    *,
    pointer_to_raw_data: int,
    size_of_data: int,
) -> bytes | None:
    """Read one debug-directory payload from the file."""
    if pointer_to_raw_data < 0:
        return None

    if size_of_data <= 0:
        return b""

    if size_of_data > MAX_DEBUG_DATA_SIZE:
        return None

    payload_end = pointer_to_raw_data + size_of_data

    if payload_end > len(sample_data):
        return None

    return sample_data[pointer_to_raw_data:payload_end]


def _parse_rsds(
    payload: bytes,
) -> tuple[
    str | None,
    str | None,
    int | None,
    bool,
]:
    """Parse an RSDS CodeView debug record."""
    minimum_size = 24

    if len(payload) < minimum_size:
        return "RSDS", None, None, True

    guid_bytes = payload[4:20]
    age = int.from_bytes(
        payload[20:24],
        byteorder="little",
    )
    pdb_path = _decode_c_string(payload[24:])

    try:
        pdb_guid = str(
            uuid.UUID(
                bytes_le=guid_bytes,
            )
        )
    except ValueError:
        pdb_guid = None

    malformed = pdb_guid is None or pdb_path is None

    return (
        "RSDS",
        pdb_guid,
        age,
        malformed,
    )


def _parse_nb10(
    payload: bytes,
) -> tuple[
    str | None,
    str | None,
    int | None,
    bool,
]:
    """Parse an NB10 CodeView debug record."""
    minimum_size = 16

    if len(payload) < minimum_size:
        return "NB10", None, None, True

    age = int.from_bytes(
        payload[12:16],
        byteorder="little",
    )
    pdb_path = _decode_c_string(payload[16:])

    return (
        "NB10",
        None,
        age,
        pdb_path is None,
    )


def _parse_codeview_payload(
    payload: bytes,
) -> tuple[
    str | None,
    str | None,
    int | None,
    str | None,
    bool,
]:
    """Parse a CodeView payload and return normalized fields."""
    if len(payload) < 4:
        return None, None, None, None, True

    signature_bytes = payload[:4]

    if signature_bytes == RSDS_SIGNATURE:
        (
            signature,
            pdb_guid,
            pdb_age,
            malformed,
        ) = _parse_rsds(payload)

        pdb_path = _decode_c_string(payload[24:]) if len(payload) >= 24 else None

        return (
            signature,
            pdb_guid,
            pdb_age,
            pdb_path,
            malformed,
        )

    if signature_bytes == NB10_SIGNATURE:
        (
            signature,
            pdb_guid,
            pdb_age,
            malformed,
        ) = _parse_nb10(payload)

        pdb_path = _decode_c_string(payload[16:]) if len(payload) >= 16 else None

        return (
            signature,
            pdb_guid,
            pdb_age,
            pdb_path,
            malformed,
        )

    signature = signature_bytes.decode(
        "ascii",
        errors="replace",
    )

    return (
        signature,
        None,
        None,
        None,
        True,
    )


def _path_is_absolute(
    pdb_path: str | None,
) -> bool:
    """Return whether a PDB path is an absolute Windows path."""
    if not pdb_path:
        return False

    path = PureWindowsPath(pdb_path)

    return bool(path.drive and path.root)


def _path_is_network_share(
    pdb_path: str | None,
) -> bool:
    """Return whether a PDB path is a UNC network path."""
    if not pdb_path:
        return False

    normalized = pdb_path.replace(
        "/",
        "\\",
    )

    return normalized.startswith("\\\\")


def _path_contains_username(
    pdb_path: str | None,
) -> bool:
    """Return whether a PDB path appears to expose a username."""
    if not pdb_path:
        return False

    normalized = pdb_path.replace(
        "/",
        "\\",
    )
    components = tuple(component for component in normalized.split("\\") if component)

    lowered = tuple(component.casefold() for component in components)

    for marker in (
        "users",
        "documents and settings",
        "home",
    ):
        if marker not in lowered:
            continue

        marker_index = lowered.index(marker)

        if marker_index + 1 < len(components):
            username = components[marker_index + 1]

            return bool(
                username
                and username.casefold()
                not in {
                    "public",
                    "default",
                    "all users",
                    "shared",
                }
            )

    return False


def _extract_debug_entries(
    pe: pefile.PE,
    sample_data: bytes,
) -> tuple[DebugDirectoryEntry, ...]:
    """Extract and normalize PE debug-directory records."""
    entries: list[DebugDirectoryEntry] = []

    debug_directory = getattr(
        pe,
        "DIRECTORY_ENTRY_DEBUG",
        (),
    )

    for index, debug_entry in enumerate(debug_directory):
        structure = getattr(
            debug_entry,
            "struct",
            None,
        )

        if structure is None:
            continue

        debug_type = int(
            getattr(
                structure,
                "Type",
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
        size_of_data = int(
            getattr(
                structure,
                "SizeOfData",
                0,
            )
        )
        address_of_raw_data = int(
            getattr(
                structure,
                "AddressOfRawData",
                0,
            )
        )
        pointer_to_raw_data = int(
            getattr(
                structure,
                "PointerToRawData",
                0,
            )
        )

        payload = _read_debug_payload(
            sample_data,
            pointer_to_raw_data=(pointer_to_raw_data),
            size_of_data=size_of_data,
        )

        signature: str | None = None
        pdb_path: str | None = None
        pdb_guid: str | None = None
        pdb_age: int | None = None

        malformed = payload is None

        if payload is not None and debug_type == CODEVIEW_TYPE:
            (
                signature,
                pdb_guid,
                pdb_age,
                pdb_path,
                codeview_malformed,
            ) = _parse_codeview_payload(payload)

            malformed = malformed or codeview_malformed

        entries.append(
            DebugDirectoryEntry(
                index=index,
                debug_type=debug_type,
                debug_type_name=(_debug_type_name(debug_type)),
                timestamp=timestamp,
                major_version=major_version,
                minor_version=minor_version,
                size_of_data=size_of_data,
                address_of_raw_data=(address_of_raw_data),
                pointer_to_raw_data=(pointer_to_raw_data),
                signature=signature,
                pdb_path=pdb_path,
                pdb_guid=pdb_guid,
                pdb_age=pdb_age,
                malformed=malformed,
                path_contains_username=(_path_contains_username(pdb_path)),
                path_is_absolute=(_path_is_absolute(pdb_path)),
                path_is_network_share=(_path_is_network_share(pdb_path)),
            )
        )

    return tuple(entries)


def _build_findings(
    data: DebugAnalysisData,
) -> tuple[Finding, ...]:
    """Generate calibrated findings from debug metadata."""
    findings: list[Finding] = []

    if not data.debug_directory_present:
        return ()

    malformed_entries = tuple(entry for entry in data.entries if entry.malformed)

    if malformed_entries:
        findings.append(
            Finding(
                title=("Malformed PE debug-directory entries detected"),
                description=(
                    "One or more PE debug-directory "
                    "records reference invalid, truncated, "
                    "or unrecognized data."
                ),
                category="pe-debug-directory",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="debug-directory",
                        value=(entry.debug_type_name),
                        location=(f"entry[{entry.index}]"),
                        metadata={
                            "type": (entry.debug_type),
                            "size": (entry.size_of_data),
                            "raw_offset": (entry.pointer_to_raw_data),
                        },
                    )
                    for entry in malformed_entries[:10]
                ),
                tags=(
                    "pe",
                    "debug",
                    "malformed",
                ),
            )
        )

    username_entries = tuple(
        entry for entry in data.entries if entry.path_contains_username and entry.pdb_path
    )

    if username_entries:
        findings.append(
            Finding(
                title=("PDB path exposes development username"),
                description=(
                    "A CodeView PDB path appears to "
                    "contain a local development username. "
                    "This metadata may support attribution "
                    "or reveal build-environment details."
                ),
                category="development-metadata",
                severity=Severity.LOW,
                confidence=80,
                evidence=tuple(
                    Evidence(
                        kind="pdb-path",
                        value=(entry.pdb_path or "unknown"),
                        location=(f"entry[{entry.index}]"),
                    )
                    for entry in username_entries[:10]
                ),
                tags=(
                    "pe",
                    "debug",
                    "pdb",
                    "username",
                ),
            )
        )

    network_entries = tuple(
        entry for entry in data.entries if entry.path_is_network_share and entry.pdb_path
    )

    if network_entries:
        findings.append(
            Finding(
                title=("PDB path references a network share"),
                description=(
                    "A CodeView PDB path references a UNC "
                    "network location, potentially exposing "
                    "internal build infrastructure."
                ),
                category="development-metadata",
                severity=Severity.LOW,
                confidence=75,
                evidence=tuple(
                    Evidence(
                        kind="pdb-path",
                        value=(entry.pdb_path or "unknown"),
                        location=(f"entry[{entry.index}]"),
                    )
                    for entry in network_entries[:10]
                ),
                tags=(
                    "pe",
                    "debug",
                    "pdb",
                    "network-share",
                ),
            )
        )

    return tuple(findings)


class DebugDirectoryAnalyzer:
    """Analyze PE debug directories and CodeView PDB records."""

    name = "debug"
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
        """Analyze PE debug-directory metadata."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()
        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            sample_data = resolved_path.read_bytes()

            pe = pefile.PE(
                str(resolved_path),
                fast_load=False,
            )

            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
                )

                entries = _extract_debug_entries(
                    pe,
                    sample_data,
                )
            finally:
                pe.close()

            pdb_paths = tuple(dict.fromkeys(entry.pdb_path for entry in entries if entry.pdb_path))

            analysis_data = DebugAnalysisData(
                debug_directory_present=bool(entries),
                entry_count=len(entries),
                codeview_entry_count=sum(entry.debug_type == CODEVIEW_TYPE for entry in entries),
                reproducible_entry_count=sum(entry.debug_type == REPRO_TYPE for entry in entries),
                malformed_entries=sum(entry.malformed for entry in entries),
                pdb_path_count=len(pdb_paths),
                username_path_count=sum(entry.path_contains_username for entry in entries),
                absolute_path_count=sum(entry.path_is_absolute for entry in entries),
                network_path_count=sum(entry.path_is_network_share for entry in entries),
                pdb_paths=pdb_paths,
                entries=entries,
            )

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
