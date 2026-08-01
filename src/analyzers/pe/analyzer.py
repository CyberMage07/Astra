"""Static analysis for Windows Portable Executable files."""

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
    PEAnalysisData,
    PEExport,
    PEHeaderInfo,
    PEImport,
    PESection,
    Severity,
)

MACHINE_TYPES: dict[int, str] = {
    0x014C: "x86",
    0x0200: "Intel Itanium",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEM_TYPES: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_NATIVE = 1

SECTION_EXECUTE = 0x20000000
SECTION_READ = 0x40000000
SECTION_WRITE = 0x80000000

SUSPICIOUS_IMPORTS: dict[str, tuple[str, Severity, str]] = {
    "CreateRemoteThread": (
        "process-injection",
        Severity.HIGH,
        "Can create a thread inside another process.",
    ),
    "WriteProcessMemory": (
        "process-injection",
        Severity.HIGH,
        "Can write data into another process address space.",
    ),
    "VirtualAllocEx": (
        "process-injection",
        Severity.HIGH,
        "Can allocate memory inside another process.",
    ),
    "OpenProcess": (
        "process-access",
        Severity.MEDIUM,
        "Can open handles to other processes.",
    ),
    "WinExec": (
        "process-execution",
        Severity.MEDIUM,
        "Can execute external programs.",
    ),
    "ShellExecuteA": (
        "process-execution",
        Severity.MEDIUM,
        "Can launch files, commands, or URLs.",
    ),
    "ShellExecuteW": (
        "process-execution",
        Severity.MEDIUM,
        "Can launch files, commands, or URLs.",
    ),
    "URLDownloadToFileA": (
        "payload-download",
        Severity.HIGH,
        "Can download a remote file.",
    ),
    "URLDownloadToFileW": (
        "payload-download",
        Severity.HIGH,
        "Can download a remote file.",
    ),
    "InternetOpenUrlA": (
        "network-access",
        Severity.MEDIUM,
        "Can access remote resources through WinINet.",
    ),
    "InternetOpenUrlW": (
        "network-access",
        Severity.MEDIUM,
        "Can access remote resources through WinINet.",
    ),
    "IsDebuggerPresent": (
        "anti-analysis",
        Severity.MEDIUM,
        "Can detect whether the process is being debugged.",
    ),
    "CheckRemoteDebuggerPresent": (
        "anti-analysis",
        Severity.MEDIUM,
        "Can detect remote debugging activity.",
    ),
    "CreateServiceA": (
        "persistence",
        Severity.HIGH,
        "Can create a Windows service.",
    ),
    "CreateServiceW": (
        "persistence",
        Severity.HIGH,
        "Can create a Windows service.",
    ),
}


def _decode_name(value: bytes | None) -> str | None:
    """Decode a PE byte string safely."""
    if value is None:
        return None

    return value.decode("utf-8", errors="replace").rstrip("\x00")


def _architecture_bits(pe: pefile.PE) -> int:
    """Return the executable architecture width."""
    return 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32


def _extract_sections(pe: pefile.PE) -> tuple[PESection, ...]:
    """Extract normalized section information."""
    sections: list[PESection] = []

    for section in pe.sections:
        characteristics = int(section.Characteristics)

        sections.append(
            PESection(
                name=_decode_name(section.Name) or "(unnamed)",
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_size=int(section.SizeOfRawData),
                entropy=float(section.get_entropy()),
                characteristics=characteristics,
                executable=bool(characteristics & SECTION_EXECUTE),
                writable=bool(characteristics & SECTION_WRITE),
                readable=bool(characteristics & SECTION_READ),
            )
        )

    return tuple(sections)


def _extract_imports(pe: pefile.PE) -> tuple[PEImport, ...]:
    """Extract imported libraries and functions."""
    imports: list[PEImport] = []

    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        library = _decode_name(descriptor.dll) or "(unknown)"

        for imported_symbol in descriptor.imports:
            function = _decode_name(imported_symbol.name)

            if function is None:
                function = f"ordinal_{imported_symbol.ordinal}"

            imports.append(
                PEImport(
                    library=library,
                    function=function,
                    address=(
                        int(imported_symbol.address)
                        if imported_symbol.address is not None
                        else None
                    ),
                    ordinal=(
                        int(imported_symbol.ordinal)
                        if imported_symbol.ordinal is not None
                        else None
                    ),
                )
            )

    return tuple(imports)


def _extract_exports(pe: pefile.PE) -> tuple[PEExport, ...]:
    """Extract exported symbols."""
    exports: list[PEExport] = []
    export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)

    if export_directory is None:
        return ()

    for symbol in export_directory.symbols:
        exports.append(
            PEExport(
                name=_decode_name(symbol.name),
                ordinal=int(symbol.ordinal),
                address=int(symbol.address),
            )
        )

    return tuple(exports)


def _overlay_size(pe: pefile.PE, sample_path: Path) -> int:
    """Calculate bytes appended beyond the parsed PE image."""
    overlay_offset = pe.get_overlay_data_start_offset()

    if overlay_offset is None:
        return 0

    file_size = sample_path.stat().st_size
    return max(0, file_size - int(overlay_offset))


def _has_tls_callbacks(pe: pefile.PE) -> bool:
    """Return whether a TLS directory with callbacks exists."""
    tls_directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)

    if tls_directory is None:
        return False

    return bool(getattr(tls_directory.struct, "AddressOfCallBacks", 0))


def _has_directory(pe: pefile.PE, directory_index: int) -> bool:
    """Return whether a PE data directory is populated."""
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY

    if directory_index >= len(directories):
        return False

    directory = directories[directory_index]
    return bool(directory.VirtualAddress and directory.Size)


def _build_data(pe: pefile.PE, sample_path: Path) -> PEAnalysisData:
    """Build normalized PE analysis data."""
    machine = MACHINE_TYPES.get(int(pe.FILE_HEADER.Machine))

    if machine is None:
        machine = f"Unknown (0x{int(pe.FILE_HEADER.Machine):04x})"

    subsystem_value = int(pe.OPTIONAL_HEADER.Subsystem)
    subsystem = SUBSYSTEM_TYPES.get(subsystem_value, f"Unknown ({subsystem_value})")
    characteristics = int(pe.FILE_HEADER.Characteristics)

    header = PEHeaderInfo(
        machine=machine,
        architecture_bits=_architecture_bits(pe),
        subsystem=subsystem,
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        entry_point=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        compile_timestamp=int(pe.FILE_HEADER.TimeDateStamp),
        number_of_sections=int(pe.FILE_HEADER.NumberOfSections),
        characteristics=characteristics,
        is_dll=bool(characteristics & IMAGE_FILE_DLL),
        is_driver=subsystem_value == IMAGE_SUBSYSTEM_NATIVE,
    )

    return PEAnalysisData(
        header=header,
        sections=_extract_sections(pe),
        imports=_extract_imports(pe),
        exports=_extract_exports(pe),
        overlay_size=_overlay_size(pe, sample_path),
        has_tls_callbacks=_has_tls_callbacks(pe),
        has_debug_directory=_has_directory(
            pe,
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        ),
        has_resources=_has_directory(
            pe,
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ),
        signed=_has_directory(
            pe,
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ),
    )


def _build_findings(data: PEAnalysisData) -> tuple[Finding, ...]:
    """Generate explainable security findings from PE metadata."""
    findings: list[Finding] = []

    for imported in data.imports:
        suspicious = SUSPICIOUS_IMPORTS.get(imported.function)

        if suspicious is None:
            continue

        category, severity, description = suspicious

        findings.append(
            Finding(
                title=f"Suspicious API import: {imported.function}",
                description=description,
                category=category,
                severity=severity,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="pe-import",
                        value=imported.function,
                        location=imported.library,
                    ),
                ),
                tags=("windows", "pe", "import"),
            )
        )

    for section in data.sections:
        if section.entropy >= 7.2:
            findings.append(
                Finding(
                    title=f"High-entropy section: {section.name}",
                    description=(
                        "The section has unusually high entropy, which may indicate "
                        "compression, encryption, or packing."
                    ),
                    category="packing",
                    severity=Severity.MEDIUM,
                    confidence=70,
                    evidence=(
                        Evidence(
                            kind="section-entropy",
                            value=f"{section.entropy:.2f}",
                            location=section.name,
                        ),
                    ),
                    tags=("pe", "entropy", "packing"),
                )
            )

        if section.executable and section.writable:
            findings.append(
                Finding(
                    title=f"Writable and executable section: {section.name}",
                    description=(
                        "The section is writable and executable, which weakens memory "
                        "protections and may support unpacking or injected code."
                    ),
                    category="memory-protection",
                    severity=Severity.HIGH,
                    confidence=85,
                    evidence=(
                        Evidence(
                            kind="section-permissions",
                            value="RWX",
                            location=section.name,
                        ),
                    ),
                    tags=("pe", "memory", "rwx"),
                )
            )

    if data.has_tls_callbacks:
        findings.append(
            Finding(
                title="TLS callbacks present",
                description=(
                    "TLS callbacks execute before the normal entry point and are "
                    "sometimes used for initialization, unpacking, or anti-analysis."
                ),
                category="execution-flow",
                severity=Severity.MEDIUM,
                confidence=65,
                evidence=(
                    Evidence(
                        kind="pe-directory",
                        value="TLS",
                        location="data directory",
                    ),
                ),
                tags=("pe", "tls", "anti-analysis"),
            )
        )

    return tuple(findings)


class PEAnalyzer:
    """Static analyzer for Windows PE binaries."""

    name = "pe"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze a PE sample and return normalized data."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        try:
            resolved_path = sample_path.expanduser().resolve()

            if not resolved_path.exists():
                raise FileNotFoundError(resolved_path)

            if not resolved_path.is_file():
                raise ValueError(f"Path is not a regular file: {resolved_path}")

            pe = pefile.PE(str(resolved_path), fast_load=False)

            try:
                pe.parse_data_directories()
                data = _build_data(pe, resolved_path)
                findings = _build_findings(data)
            finally:
                pe.close()

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.COMPLETED,
                started_at=started_at,
                duration_ms=duration_ms,
                findings=findings,
                data=data.model_dump(mode="json"),
            )

        except (FileNotFoundError, ValueError):
            raise
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
