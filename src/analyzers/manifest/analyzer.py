"""PE application-manifest analysis for Astra."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

import pefile

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    ManifestAnalysisData,
    ManifestDependency,
    Severity,
)

RT_MANIFEST = 24

MANIFEST_NAMESPACES = {
    "asmv1": "urn:schemas-microsoft-com:asm.v1",
    "asmv3": "urn:schemas-microsoft-com:asm.v3",
    "compat": "urn:schemas-microsoft-com:compatibility.v1",
    "ws2005": "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
    "ws2016": "http://schemas.microsoft.com/SMI/2016/WindowsSettings",
}


def _decode_manifest(
    data: bytes,
) -> str:
    """Decode manifest XML using common Windows encodings."""
    if data.startswith(b"\xff\xfe"):
        return data.decode(
            "utf-16-le",
            errors="replace",
        )

    if data.startswith(b"\xfe\xff"):
        return data.decode(
            "utf-16-be",
            errors="replace",
        )

    return data.decode(
        "utf-8",
        errors="replace",
    )


def _extract_manifest_blobs(
    pe: pefile.PE,
) -> tuple[bytes, ...]:
    """Extract RT_MANIFEST resources from a PE."""
    resources = getattr(
        pe,
        "DIRECTORY_ENTRY_RESOURCE",
        None,
    )

    if resources is None:
        return ()

    blobs: list[bytes] = []

    for type_entry in getattr(
        resources,
        "entries",
        (),
    ):
        type_id = getattr(
            type_entry,
            "id",
            None,
        )

        if type_id != RT_MANIFEST:
            continue

        directory = getattr(
            type_entry,
            "directory",
            None,
        )

        if directory is None:
            continue

        for name_entry in getattr(
            directory,
            "entries",
            (),
        ):
            language_directory = getattr(
                name_entry,
                "directory",
                None,
            )

            if language_directory is None:
                continue

            for language_entry in getattr(
                language_directory,
                "entries",
                (),
            ):
                data_entry = getattr(
                    language_entry,
                    "data",
                    None,
                )

                struct = getattr(
                    data_entry,
                    "struct",
                    None,
                )

                if struct is None:
                    continue

                rva = int(
                    getattr(
                        struct,
                        "OffsetToData",
                        0,
                    )
                )
                size = int(
                    getattr(
                        struct,
                        "Size",
                        0,
                    )
                )

                if rva <= 0 or size <= 0:
                    continue

                blob = pe.get_data(
                    rva,
                    size,
                )

                if blob:
                    blobs.append(bytes(blob))

    return tuple(blobs)


def _find_execution_level(
    root: ET.Element,
) -> tuple[
    str | None,
    bool | None,
    bool,
]:
    """Extract requestedExecutionLevel attributes."""
    nodes = root.findall(
        ".//asmv3:requestedExecutionLevel",
        MANIFEST_NAMESPACES,
    )

    if not nodes:
        nodes = root.findall(
            ".//asmv1:requestedExecutionLevel",
            MANIFEST_NAMESPACES,
        )

    if not nodes:
        return None, None, False

    node = nodes[0]

    level = node.attrib.get("level")

    ui_access_raw = node.attrib.get("uiAccess")

    ui_access: bool | None = None

    if ui_access_raw is not None:
        ui_access = ui_access_raw.casefold() == "true"

    return (
        level,
        ui_access,
        True,
    )


def _find_auto_elevate(
    root: ET.Element,
) -> bool:
    """Return whether autoElevate is enabled."""
    for element in root.iter():
        tag = element.tag

        if not isinstance(tag, str):
            continue

        if tag.endswith("autoElevate"):
            text = (element.text or "").strip()

            return text.casefold() == "true"

    return False


def _find_dpi_aware(
    root: ET.Element,
) -> bool | None:
    """Extract dpiAware setting."""
    for element in root.iter():
        tag = element.tag

        if not isinstance(tag, str):
            continue

        if tag.endswith("dpiAware"):
            text = (element.text or "").strip()

            if not text:
                return None

            return text.casefold() in {
                "true",
                "true/pm",
                "permonitor",
                "permonitorv2",
            }

    return None


def _find_long_path_aware(
    root: ET.Element,
) -> bool | None:
    """Extract longPathAware setting."""
    for element in root.iter():
        tag = element.tag

        if not isinstance(tag, str):
            continue

        if tag.endswith("longPathAware"):
            text = (element.text or "").strip()

            if not text:
                return None

            return text.casefold() == "true"

    return None


def _extract_supported_os(
    root: ET.Element,
) -> tuple[str, ...]:
    """Extract supportedOS GUIDs."""
    values: list[str] = []

    for element in root.iter():
        tag = element.tag

        if not isinstance(tag, str):
            continue

        if not tag.endswith("supportedOS"):
            continue

        value = element.attrib.get("Id")

        if value:
            values.append(value)

    return tuple(dict.fromkeys(values))


def _extract_dependencies(
    root: ET.Element,
) -> tuple[ManifestDependency, ...]:
    """Extract only true dependent-assembly identities."""
    dependencies: list[ManifestDependency] = []

    for dependency_node in root.iter():
        dependency_tag = dependency_node.tag

        if not isinstance(dependency_tag, str):
            continue

        local_dependency_tag = dependency_tag.rsplit("}", 1)[-1]

        if local_dependency_tag != "dependency":
            continue

        for dependent_assembly in dependency_node:
            dependent_tag = dependent_assembly.tag

            if not isinstance(dependent_tag, str):
                continue

            local_dependent_tag = dependent_tag.rsplit("}", 1)[-1]

            if local_dependent_tag != "dependentAssembly":
                continue

            for identity in dependent_assembly:
                identity_tag = identity.tag

                if not isinstance(identity_tag, str):
                    continue

                local_identity_tag = identity_tag.rsplit("}", 1)[-1]

                if local_identity_tag != "assemblyIdentity":
                    continue

                name = identity.attrib.get("name")

                if not name:
                    continue

                dependencies.append(
                    ManifestDependency(
                        name=name,
                        version=identity.attrib.get("version"),
                        processor_architecture=identity.attrib.get("processorArchitecture"),
                        public_key_token=identity.attrib.get("publicKeyToken"),
                        language=identity.attrib.get("language"),
                        dependency_type=identity.attrib.get("type"),
                    )
                )

    unique: dict[
        tuple[
            str,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
        ],
        ManifestDependency,
    ] = {}

    for manifest_dependency in dependencies:
        key = (
            manifest_dependency.name,
            manifest_dependency.version,
            manifest_dependency.processor_architecture,
            manifest_dependency.public_key_token,
            manifest_dependency.language,
            manifest_dependency.dependency_type,
        )

        unique[key] = manifest_dependency

    return tuple(unique.values())


def _parse_manifest(
    blob: bytes,
) -> ManifestAnalysisData:
    """Parse one manifest blob."""
    text = _decode_manifest(blob)

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ManifestAnalysisData(
            manifest_present=True,
            manifest_count=1,
            raw_manifest_count=1,
            malformed=True,
        )

    (
        execution_level,
        ui_access,
        privileges_present,
    ) = _find_execution_level(root)

    dependencies = _extract_dependencies(root)

    supported_os_ids = _extract_supported_os(root)

    normalized_level = execution_level.casefold() if execution_level else None

    return ManifestAnalysisData(
        manifest_present=True,
        manifest_count=1,
        requested_execution_level=(execution_level),
        ui_access=ui_access,
        requires_administrator=(normalized_level == "requireadministrator"),
        highest_available=(normalized_level == "highestavailable"),
        as_invoker=(normalized_level == "asinvoker"),
        auto_elevate=(_find_auto_elevate(root)),
        dpi_aware=(_find_dpi_aware(root)),
        long_path_aware=(_find_long_path_aware(root)),
        supported_os_count=len(supported_os_ids),
        supported_os_ids=(supported_os_ids),
        dependency_count=len(dependencies),
        dependencies=(dependencies),
        requested_privileges_present=(privileges_present),
        malformed=False,
        raw_manifest_count=1,
    )


def _merge_manifests(
    parsed: tuple[
        ManifestAnalysisData,
        ...,
    ],
) -> ManifestAnalysisData:
    """Merge multiple manifest-resource results."""
    if not parsed:
        return ManifestAnalysisData(
            manifest_present=False,
        )

    malformed = any(item.malformed for item in parsed)

    execution_level = next(
        (item.requested_execution_level for item in parsed if item.requested_execution_level),
        None,
    )

    ui_access = next(
        (item.ui_access for item in parsed if item.ui_access is not None),
        None,
    )

    dpi_aware = next(
        (item.dpi_aware for item in parsed if item.dpi_aware is not None),
        None,
    )

    long_path_aware = next(
        (item.long_path_aware for item in parsed if item.long_path_aware is not None),
        None,
    )

    supported_os_ids = tuple(
        dict.fromkeys(os_id for item in parsed for os_id in item.supported_os_ids)
    )

    dependencies = tuple(
        {
            (
                dependency.name,
                dependency.version,
                dependency.processor_architecture,
                dependency.public_key_token,
                dependency.language,
                dependency.dependency_type,
            ): dependency
            for item in parsed
            for dependency in item.dependencies
        }.values()
    )

    return ManifestAnalysisData(
        manifest_present=True,
        manifest_count=len(parsed),
        requested_execution_level=(execution_level),
        ui_access=ui_access,
        requires_administrator=any(item.requires_administrator for item in parsed),
        highest_available=any(item.highest_available for item in parsed),
        as_invoker=any(item.as_invoker for item in parsed),
        auto_elevate=any(item.auto_elevate for item in parsed),
        dpi_aware=dpi_aware,
        long_path_aware=(long_path_aware),
        supported_os_count=len(supported_os_ids),
        supported_os_ids=(supported_os_ids),
        dependency_count=len(dependencies),
        dependencies=(dependencies),
        requested_privileges_present=any(item.requested_privileges_present for item in parsed),
        malformed=malformed,
        raw_manifest_count=len(parsed),
    )


def _build_findings(
    data: ManifestAnalysisData,
) -> tuple[Finding, ...]:
    """Generate conservative manifest findings."""
    findings: list[Finding] = []

    if not data.manifest_present:
        return ()

    if data.malformed:
        findings.append(
            Finding(
                title=("Malformed PE application manifest detected"),
                description=(
                    "One or more embedded Windows application "
                    "manifest resources could not be parsed as "
                    "valid XML."
                ),
                category="pe-manifest",
                severity=Severity.LOW,
                confidence=80,
                evidence=(
                    Evidence(
                        kind="manifest",
                        value="malformed",
                        location="RT_MANIFEST resource",
                    ),
                ),
                tags=(
                    "pe",
                    "manifest",
                    "malformed",
                ),
            )
        )

    if data.auto_elevate:
        findings.append(
            Finding(
                title=("Manifest requests automatic elevation"),
                description=(
                    "The application manifest enables autoElevate. "
                    "This is security-relevant because the process "
                    "may request elevated execution depending on "
                    "Windows policy and trust context."
                ),
                category="privilege-escalation",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="manifest-setting",
                        value="autoElevate=true",
                        location="Windows application manifest",
                    ),
                ),
                tags=(
                    "pe",
                    "manifest",
                    "elevation",
                ),
            )
        )

    if data.ui_access is True:
        findings.append(
            Finding(
                title=("Manifest enables UIAccess"),
                description=(
                    "The application requests UIAccess privileges. "
                    "This can permit interaction with higher-integrity "
                    "user-interface elements when Windows requirements "
                    "for UIAccess applications are satisfied."
                ),
                category="privilege",
                severity=Severity.MEDIUM,
                confidence=75,
                evidence=(
                    Evidence(
                        kind="manifest-setting",
                        value="uiAccess=true",
                        location="requestedExecutionLevel",
                    ),
                ),
                tags=(
                    "pe",
                    "manifest",
                    "uiaccess",
                ),
            )
        )

    if data.requires_administrator and data.ui_access is True:
        findings.append(
            Finding(
                title=("Manifest combines administrator elevation with UIAccess"),
                description=(
                    "The application requests administrator "
                    "execution and UIAccess simultaneously. "
                    "This combination is security-sensitive "
                    "and should be correlated with signature, "
                    "installation context, and behavior."
                ),
                category="privilege",
                severity=Severity.MEDIUM,
                confidence=80,
                evidence=(
                    Evidence(
                        kind="manifest-setting",
                        value=("requireAdministrator + uiAccess"),
                        location="requestedExecutionLevel",
                    ),
                ),
                tags=(
                    "pe",
                    "manifest",
                    "elevation",
                    "uiaccess",
                ),
            )
        )

    return tuple(findings)


class ManifestAnalyzer:
    """Analyze Windows PE application manifests."""

    name = "manifest"
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
        """Analyze embedded PE application manifests."""
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
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
                )

                blobs = _extract_manifest_blobs(pe)

                parsed = tuple(_parse_manifest(blob) for blob in blobs)

                analysis_data = _merge_manifests(parsed)
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
