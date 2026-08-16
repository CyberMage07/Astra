"""Bounded recursive embedded-payload analysis for Astra."""

from __future__ import annotations

import hashlib
import math
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import magic
import pefile

from packages.schemas import (
    AnalysisReport,
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    EmbeddedAnalysisData,
    EmbeddedAnalysisLimits,
    EmbeddedPayloadAnalysisSummary,
    EmbeddedPayloadEntry,
    EmbeddedPayloadIdentity,
    EmbeddedPayloadLocation,
    Evidence,
    Finding,
    Severity,
)

ChildAnalyzer = Callable[
    [Path],
    AnalysisReport,
]

DEFAULT_LIMITS = EmbeddedAnalysisLimits()

EXECUTABLE_FAMILIES = {
    "pe",
    "elf",
    "macho",
    "apk",
    "dex",
}

ARCHIVE_FAMILIES = {
    "archive",
    "zip",
    "rar",
    "7z",
    "tar",
    "gzip",
    "bzip2",
    "xz",
}

DOCUMENT_FAMILIES = {
    "pdf",
    "office",
    "document",
    "rtf",
}

SCRIPT_FAMILIES = {
    "script",
    "shell",
    "python",
    "javascript",
    "powershell",
}

MINIMUM_CANDIDATE_SIZE = 32

KNOWN_SIGNATURES: tuple[
    tuple[
        bytes,
        str,
        str,
    ],
    ...,
] = (
    (
        b"MZ",
        "pe",
        "application/vnd.microsoft.portable-executable",
    ),
    (
        b"\x7fELF",
        "elf",
        "application/x-executable",
    ),
    (
        b"\xfe\xed\xfa\xce",
        "macho",
        "application/x-mach-binary",
    ),
    (
        b"\xce\xfa\xed\xfe",
        "macho",
        "application/x-mach-binary",
    ),
    (
        b"\xfe\xed\xfa\xcf",
        "macho",
        "application/x-mach-binary",
    ),
    (
        b"\xcf\xfa\xed\xfe",
        "macho",
        "application/x-mach-binary",
    ),
    (
        b"PK\x03\x04",
        "archive",
        "application/zip",
    ),
    (
        b"%PDF-",
        "pdf",
        "application/pdf",
    ),
    (
        b"\x89PNG\r\n\x1a\n",
        "image",
        "image/png",
    ),
    (
        b"\xff\xd8\xff",
        "image",
        "image/jpeg",
    ),
)


@dataclass
class _Candidate:
    """Raw embedded-payload candidate."""

    data: bytes
    location: EmbeddedPayloadLocation
    extraction_method: str


@dataclass
class _RecursionState:
    """Global state shared by one recursive analysis tree."""

    seen_hashes: set[str] = field(default_factory=set)

    payloads: list[EmbeddedPayloadEntry] = field(default_factory=list)

    total_extracted_bytes: int = 0
    skipped_payload_count: int = 0
    maximum_depth_reached: int = 0

    recursion_limit_reached: bool = False
    payload_limit_reached: bool = False
    byte_limit_reached: bool = False


def _entropy(
    data: bytes,
) -> float:
    """Calculate Shannon entropy."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _sha256(
    data: bytes,
) -> str:
    """Return payload SHA-256."""
    return hashlib.sha256(data).hexdigest()


def _resource_type_name(
    entry: object,
) -> str | None:
    """Return a readable PE resource type."""
    name = getattr(
        entry,
        "name",
        None,
    )

    if name is not None:
        return str(name)

    structure = getattr(
        entry,
        "struct",
        None,
    )

    resource_id = getattr(
        structure,
        "Id",
        None,
    )

    if resource_id is None:
        return None

    return str(resource_id)


def _resource_entry_name(
    entry: object,
) -> str | None:
    """Return a readable resource name."""
    name = getattr(
        entry,
        "name",
        None,
    )

    if name is not None:
        return str(name)

    structure = getattr(
        entry,
        "struct",
        None,
    )

    resource_id = getattr(
        structure,
        "Id",
        None,
    )

    if resource_id is None:
        return None

    return str(resource_id)


def _guess_family_from_signature(
    data: bytes,
) -> tuple[
    str,
    str,
]:
    """Identify common embedded formats from signatures."""
    for (
        signature,
        family,
        mime_type,
    ) in KNOWN_SIGNATURES:
        if data.startswith(signature):
            return (
                family,
                mime_type,
            )

    return (
        "unknown",
        "application/octet-stream",
    )


def _magic_description(
    data: bytes,
) -> tuple[
    str,
    str,
    str,
]:
    """Identify bytes using libmagic plus signature fallback."""
    (
        fallback_family,
        fallback_mime,
    ) = _guess_family_from_signature(data)

    try:
        description = magic.from_buffer(data)

        mime_type = magic.from_buffer(
            data,
            mime=True,
        )

        if not isinstance(
            description,
            str,
        ):
            description = "Unknown embedded data"

        if not isinstance(
            mime_type,
            str,
        ):
            mime_type = fallback_mime

    except Exception:
        description = "Unknown embedded data"
        mime_type = fallback_mime

    family = fallback_family

    normalized_description = description.casefold()

    normalized_mime = mime_type.casefold()

    if (
        "portable executable" in normalized_description
        or "ms-dos executable" in normalized_description
    ):
        family = "pe"

    elif "elf" in normalized_description:
        family = "elf"

    elif "mach-o" in normalized_description:
        family = "macho"

    elif normalized_mime == "application/pdf":
        family = "pdf"

    elif "zip" in normalized_description or normalized_mime in {
        "application/zip",
        "application/x-7z-compressed",
        "application/vnd.rar",
    }:
        family = "archive"

    return (
        family,
        mime_type,
        description,
    )


def _payload_identity(
    data: bytes,
) -> EmbeddedPayloadIdentity:
    """Build normalized payload identity."""
    (
        family,
        mime_type,
        description,
    ) = _magic_description(data)

    return EmbeddedPayloadIdentity(
        sha256=_sha256(data),
        detected_family=family,
        mime_type=mime_type,
        magic_description=description,
        is_executable=(family in EXECUTABLE_FAMILIES),
    )


def _is_interesting(
    data: bytes,
) -> bool:
    """Return whether candidate resembles a standalone file."""
    family, _ = _guess_family_from_signature(data)

    return family != "unknown"


def _extract_pe_resources(
    pe: pefile.PE,
    raw_data: bytes,
) -> list[_Candidate]:
    """Extract raw PE resource candidates."""
    candidates: list[_Candidate] = []

    root = getattr(
        pe,
        "DIRECTORY_ENTRY_RESOURCE",
        None,
    )

    if root is None:
        return candidates

    for type_entry in getattr(
        root,
        "entries",
        (),
    ):
        resource_type = _resource_type_name(type_entry)

        type_directory = getattr(
            type_entry,
            "directory",
            None,
        )

        if type_directory is None:
            continue

        for name_entry in getattr(
            type_directory,
            "entries",
            (),
        ):
            resource_name = _resource_entry_name(name_entry)

            name_directory = getattr(
                name_entry,
                "directory",
                None,
            )

            if name_directory is None:
                continue

            for language_entry in getattr(
                name_directory,
                "entries",
                (),
            ):
                data_entry = getattr(
                    language_entry,
                    "data",
                    None,
                )

                structure = getattr(
                    data_entry,
                    "struct",
                    None,
                )

                if structure is None:
                    continue

                rva = int(
                    getattr(
                        structure,
                        "OffsetToData",
                        0,
                    )
                )

                size = int(
                    getattr(
                        structure,
                        "Size",
                        0,
                    )
                )

                if size < MINIMUM_CANDIDATE_SIZE:
                    continue

                try:
                    offset = int(pe.get_offset_from_rva(rva))
                except Exception:
                    continue

                if offset < 0 or offset >= len(raw_data):
                    continue

                end = min(
                    len(raw_data),
                    offset + size,
                )

                payload = raw_data[offset:end]

                if len(payload) < MINIMUM_CANDIDATE_SIZE:
                    continue

                candidates.append(
                    _Candidate(
                        data=payload,
                        location=(
                            EmbeddedPayloadLocation(
                                source=("resource"),
                                offset=offset,
                                size=len(payload),
                                resource_type=(resource_type),
                                resource_name=(resource_name),
                            )
                        ),
                        extraction_method=("pe-resource"),
                    )
                )

    return candidates


def _extract_pe_overlay(
    pe: pefile.PE,
    raw_data: bytes,
) -> list[_Candidate]:
    """Extract PE overlay candidate."""
    try:
        raw_offset = pe.get_overlay_data_start_offset()
    except Exception:
        return []

    if raw_offset is None:
        return []

    offset = int(raw_offset)

    if offset < 0 or offset >= len(raw_data):
        return []

    payload = raw_data[offset:]

    if len(payload) < MINIMUM_CANDIDATE_SIZE:
        return []

    return [
        _Candidate(
            data=payload,
            location=(
                EmbeddedPayloadLocation(
                    source="overlay",
                    offset=offset,
                    size=len(payload),
                )
            ),
            extraction_method=("pe-overlay"),
        )
    ]


def _extract_pe_candidates(
    sample_path: Path,
) -> list[_Candidate]:
    """Extract candidates from one PE sample."""
    raw_data = sample_path.read_bytes()

    pe = pefile.PE(
        str(sample_path),
        fast_load=False,
    )

    try:
        return _extract_pe_resources(
            pe,
            raw_data,
        ) + _extract_pe_overlay(
            pe,
            raw_data,
        )

    finally:
        pe.close()


def _analysis_summary(
    report: AnalysisReport,
) -> EmbeddedPayloadAnalysisSummary:
    """Convert a child report into compact embedded metadata."""
    assessment = report.assessment

    return EmbeddedPayloadAnalysisSummary(
        analyzed=True,
        analyzer_count=len(report.analyzer_results),
        completed_analyzers=(report.completed_analyzers),
        failed_analyzers=(report.failed_analyzers),
        finding_count=len(report.findings),
        classification=(assessment.classification.value if assessment is not None else None),
        risk_score=(assessment.score if assessment is not None else None),
        confidence=(assessment.confidence if assessment is not None else None),
    )


def _suffix_for_family(
    family: str,
) -> str:
    """Return a useful temporary-file suffix."""
    suffixes = {
        "pe": ".exe",
        "elf": ".elf",
        "macho": ".macho",
        "archive": ".zip",
        "pdf": ".pdf",
        "image": ".bin",
    }

    return suffixes.get(
        family,
        ".bin",
    )


class EmbeddedAnalyzer:
    """Discover and recursively analyze embedded payloads."""

    name = "embedded"
    version = "0.2.0"

    supported_families = frozenset(
        {
            "pe",
        }
    )

    def __init__(
        self,
        limits: (EmbeddedAnalysisLimits | None) = None,
        child_analyzer: (ChildAnalyzer | None) = None,
    ) -> None:
        """Initialize bounded recursive analysis."""
        self.limits = limits if limits is not None else DEFAULT_LIMITS

        self.child_analyzer = child_analyzer

    def supports(
        self,
        family: str,
    ) -> bool:
        """Return whether discovery supports the family."""
        return family in self.supported_families

    def _discover_candidates(
        self,
        sample_path: Path,
        family: str,
    ) -> list[_Candidate]:
        """Dispatch candidate extraction by parent family."""
        if family == "pe":
            return _extract_pe_candidates(sample_path)

        return []

    def _analyze_child_bytes(
        self,
        data: bytes,
        identity: EmbeddedPayloadIdentity,
    ) -> EmbeddedPayloadAnalysisSummary:
        """Run normal Astra analysis on one child sample."""
        if self.child_analyzer is None:
            return EmbeddedPayloadAnalysisSummary(analyzed=False)

        suffix = _suffix_for_family(identity.detected_family)

        try:
            with tempfile.NamedTemporaryFile(
                prefix="astra-embedded-",
                suffix=suffix,
                delete=True,
            ) as temporary:
                temporary.write(data)
                temporary.flush()

                report = self.child_analyzer(Path(temporary.name))

            return _analysis_summary(report)

        except Exception:
            return EmbeddedPayloadAnalysisSummary(analyzed=False)

    def _walk(
        self,
        sample_path: Path,
        family: str,
        *,
        depth: int,
        parent_index: (int | None),
        state: _RecursionState,
    ) -> None:
        """Walk one level of the embedded-payload tree."""
        if depth > self.limits.maximum_depth:
            state.recursion_limit_reached = True
            return

        state.maximum_depth_reached = max(
            state.maximum_depth_reached,
            depth - 1,
        )

        candidates = self._discover_candidates(
            sample_path,
            family,
        )

        for candidate in candidates:
            if len(state.payloads) >= self.limits.maximum_payloads:
                state.payload_limit_reached = True
                return

            raw_payload = candidate.data
            truncated = False

            if len(raw_payload) > self.limits.maximum_payload_size:
                raw_payload = raw_payload[: self.limits.maximum_payload_size]
                truncated = True

            remaining_budget = (
                self.limits.maximum_total_extracted_bytes - state.total_extracted_bytes
            )

            if remaining_budget <= 0:
                state.byte_limit_reached = True
                return

            if len(raw_payload) > remaining_budget:
                raw_payload = raw_payload[:remaining_budget]
                truncated = True
                state.byte_limit_reached = True

            if len(raw_payload) < MINIMUM_CANDIDATE_SIZE:
                state.skipped_payload_count += 1
                continue

            if not _is_interesting(raw_payload):
                state.skipped_payload_count += 1
                continue

            identity = _payload_identity(raw_payload)

            duplicate = identity.sha256 in state.seen_hashes

            index = len(state.payloads)

            if duplicate:
                state.skipped_payload_count += 1

                analysis = EmbeddedPayloadAnalysisSummary(analyzed=False)

            else:
                state.seen_hashes.add(identity.sha256)

                if truncated:
                    state.skipped_payload_count += 1

                    analysis = EmbeddedPayloadAnalysisSummary(analyzed=False)

                else:
                    analysis = self._analyze_child_bytes(
                        raw_payload,
                        identity,
                    )

            state.total_extracted_bytes += len(raw_payload)

            payload_entry = EmbeddedPayloadEntry(
                index=index,
                parent_index=(parent_index),
                depth=depth,
                location=(candidate.location),
                identity=identity,
                entropy=_entropy(raw_payload),
                extraction_method=(candidate.extraction_method),
                duplicate=duplicate,
                truncated=truncated,
                analysis=analysis,
            )

            state.payloads.append(payload_entry)

            state.maximum_depth_reached = max(
                state.maximum_depth_reached,
                depth,
            )

            if state.byte_limit_reached:
                return

            if duplicate or truncated:
                continue

            if identity.detected_family not in self.supported_families:
                continue

            if depth >= self.limits.maximum_depth:
                state.recursion_limit_reached = True
                continue

            suffix = _suffix_for_family(identity.detected_family)

            try:
                with tempfile.NamedTemporaryFile(
                    prefix=("astra-embedded-recursive-"),
                    suffix=suffix,
                    delete=True,
                ) as temporary:
                    temporary.write(raw_payload)
                    temporary.flush()

                    self._walk(
                        Path(temporary.name),
                        identity.detected_family,
                        depth=depth + 1,
                        parent_index=index,
                        state=state,
                    )

            except Exception:
                state.skipped_payload_count += 1

    def _extract_data(
        self,
        sample_path: Path,
    ) -> EmbeddedAnalysisData:
        """Build complete bounded recursive analysis data."""
        state = _RecursionState()

        root_data = sample_path.read_bytes()
        state.seen_hashes.add(_sha256(root_data))

        self._walk(
            sample_path,
            "pe",
            depth=1,
            parent_index=None,
            state=state,
        )

        payloads = tuple(state.payloads)

        return EmbeddedAnalysisData(
            embedded_payloads_present=bool(payloads),
            payload_count=len(payloads),
            analyzed_payload_count=sum(payload.analysis.analyzed for payload in payloads),
            executable_payload_count=sum(
                payload.identity.detected_family in EXECUTABLE_FAMILIES for payload in payloads
            ),
            archive_payload_count=sum(
                payload.identity.detected_family in ARCHIVE_FAMILIES for payload in payloads
            ),
            document_payload_count=sum(
                payload.identity.detected_family in DOCUMENT_FAMILIES for payload in payloads
            ),
            script_payload_count=sum(
                payload.identity.detected_family in SCRIPT_FAMILIES for payload in payloads
            ),
            duplicate_payload_count=sum(payload.duplicate for payload in payloads),
            skipped_payload_count=(state.skipped_payload_count),
            maximum_depth_reached=(state.maximum_depth_reached),
            total_extracted_bytes=(state.total_extracted_bytes),
            recursion_limit_reached=(state.recursion_limit_reached),
            payload_limit_reached=(state.payload_limit_reached),
            byte_limit_reached=(state.byte_limit_reached),
            limits=self.limits,
            payloads=payloads,
        )

    @staticmethod
    def _build_findings(
        data: EmbeddedAnalysisData,
    ) -> tuple[Finding, ...]:
        """Generate conservative embedded-payload findings."""
        findings: list[Finding] = []

        executable_payloads = tuple(
            payload
            for payload in data.payloads
            if (payload.identity.is_executable and not payload.duplicate)
        )

        if executable_payloads:
            findings.append(
                Finding(
                    title=("Embedded executable payloads detected"),
                    description=(
                        "One or more extracted regions "
                        "contain recognizable executable "
                        "payloads. This may be legitimate "
                        "installer content but warrants "
                        "recursive analysis."
                    ),
                    category=("embedded-payload"),
                    severity=(Severity.MEDIUM),
                    confidence=75,
                    evidence=tuple(
                        Evidence(
                            kind=("embedded-file"),
                            value=(payload.identity.detected_family),
                            location=(payload.location.source),
                            metadata={
                                "sha256": (payload.identity.sha256),
                                "size": (payload.location.size),
                                "depth": (payload.depth),
                            },
                        )
                        for payload in executable_payloads[:20]
                    ),
                    tags=(
                        "embedded",
                        "payload",
                        "executable",
                    ),
                )
            )

        if data.recursion_limit_reached or data.payload_limit_reached or data.byte_limit_reached:
            findings.append(
                Finding(
                    title=("Embedded payload analysis limits reached"),
                    description=("One or more bounded-recursion safety limits were reached."),
                    category=("embedded-analysis"),
                    severity=(Severity.INFO),
                    confidence=95,
                    evidence=(
                        Evidence(
                            kind=("analysis-limit"),
                            value="reached",
                            location=("embedded analyzer"),
                            metadata={
                                "recursion_limit": (data.recursion_limit_reached),
                                "payload_limit": (data.payload_limit_reached),
                                "byte_limit": (data.byte_limit_reached),
                            },
                        ),
                    ),
                    tags=(
                        "embedded",
                        "limits",
                    ),
                )
            )

        return tuple(findings)

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisResult:
        """Discover and recursively analyze embedded payloads."""
        started_at = datetime.now(UTC)

        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            analysis_data = self._extract_data(resolved_path)

            findings = self._build_findings(analysis_data)

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.COMPLETED),
                started_at=(started_at),
                duration_ms=(duration_ms),
                findings=findings,
                data=(analysis_data.model_dump(mode="json")),
            )

        except pefile.PEFormatError as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=(self.version),
                status=(AnalysisStatus.FAILED),
                started_at=(started_at),
                duration_ms=(duration_ms),
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
                analyzer_version=(self.version),
                status=(AnalysisStatus.PARTIAL),
                started_at=(started_at),
                duration_ms=(duration_ms),
                errors=(
                    AnalyzerError(
                        error_type=(type(error).__name__),
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
