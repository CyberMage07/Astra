"""Evidence-based PE packer detection for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from analyzers.pe import PEAnalyzer
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    Evidence,
    Finding,
    PackerAnalysisData,
    PackerCandidate,
    PackerIndicator,
    Severity,
)

HIGH_ENTROPY_THRESHOLD = 7.2
LOW_IMPORT_THRESHOLD = 15
LARGE_OVERLAY_THRESHOLD = 1024 * 1024
PACKED_CONFIDENCE_THRESHOLD = 60

KNOWN_PACKER_SECTIONS: dict[str, str] = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".upx": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "mpress1": "MPRESS",
    "mpress2": "MPRESS",
    ".mpress": "MPRESS",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    "vmp0": "VMProtect",
    "vmp1": "VMProtect",
    "vmp2": "VMProtect",
    ".themida": "Themida",
    ".winlice": "Themida",
    "themida": "Themida",
    ".petite": "Petite",
    ".pec1": "PECompact",
    ".pec2": "PECompact",
    ".boom": "Boomerang",
}


def _section_name(value: object) -> str:
    """Normalize a PE section name."""
    return str(value).strip().lower()


def _build_packer_candidate(
    packer_name: str,
    indicators: list[PackerIndicator],
) -> PackerCandidate:
    """Build a normalized packer candidate from matching indicators."""
    confidence = min(
        100,
        max(
            (indicator.confidence for indicator in indicators),
            default=0,
        )
        + max(0, len(indicators) - 1) * 10,
    )

    return PackerCandidate(
        name=packer_name,
        confidence=confidence,
        indicators=tuple(indicators),
    )


class PackerAnalyzer:
    """Detect packing and executable protection using PE heuristics."""

    name = "packer"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze a PE sample for packing indicators."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        pe_result = PEAnalyzer().analyze(sample_path)

        if pe_result.status is not AnalysisStatus.COMPLETED:
            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=pe_result.status,
                started_at=started_at,
                duration_ms=int((time.perf_counter() - start) * 1000),
                errors=pe_result.errors,
            )

        data = pe_result.data
        sections = data["sections"]
        imports = data["imports"]
        overlay_size = int(data["overlay_size"])

        indicators: list[PackerIndicator] = []
        candidate_indicators: dict[str, list[PackerIndicator]] = {}

        high_entropy_sections = 0
        executable_writable_sections = 0
        suspicious_section_names = 0

        for section in sections:
            section_name = _section_name(section["name"])
            entropy = float(section["entropy"])
            executable = bool(section["executable"])
            writable = bool(section["writable"])

            if entropy >= HIGH_ENTROPY_THRESHOLD:
                high_entropy_sections += 1

                indicators.append(
                    PackerIndicator(
                        indicator_type="high-entropy-section",
                        description=(
                            "The section has high entropy, which may indicate "
                            "compression, encryption, or packed content."
                        ),
                        value=f"{entropy:.2f}",
                        confidence=65,
                        severity=Severity.MEDIUM,
                        location=str(section["name"]),
                    )
                )

            if executable and writable:
                executable_writable_sections += 1

                indicators.append(
                    PackerIndicator(
                        indicator_type="rwx-section",
                        description=(
                            "The section is both writable and executable, a pattern "
                            "commonly used by unpacking stubs and runtime loaders."
                        ),
                        value="RWX",
                        confidence=75,
                        severity=Severity.HIGH,
                        location=str(section["name"]),
                    )
                )

            packer_name = KNOWN_PACKER_SECTIONS.get(section_name)

            if packer_name is not None:
                suspicious_section_names += 1

                indicator = PackerIndicator(
                    indicator_type="known-packer-section",
                    description=(f"The section name is associated with the {packer_name} packer."),
                    value=str(section["name"]),
                    confidence=90,
                    severity=Severity.HIGH,
                    location=str(section["name"]),
                )

                indicators.append(indicator)
                candidate_indicators.setdefault(packer_name, []).append(indicator)

        if len(imports) <= LOW_IMPORT_THRESHOLD:
            indicators.append(
                PackerIndicator(
                    indicator_type="low-import-count",
                    description=(
                        "The executable has an unusually small import table, which "
                        "may indicate runtime API resolution or a packed loader."
                    ),
                    value=str(len(imports)),
                    confidence=55,
                    severity=Severity.MEDIUM,
                    location="PE import table",
                )
            )

        if overlay_size >= LARGE_OVERLAY_THRESHOLD:
            indicators.append(
                PackerIndicator(
                    indicator_type="large-overlay",
                    description=(
                        "A large amount of data exists beyond the parsed PE image. "
                        "This can contain compressed payloads or installer data."
                    ),
                    value=str(overlay_size),
                    confidence=45,
                    severity=Severity.LOW,
                    location="PE overlay",
                )
            )

        candidates = tuple(
            sorted(
                (
                    _build_packer_candidate(name, candidate_evidence)
                    for name, candidate_evidence in candidate_indicators.items()
                ),
                key=lambda candidate: candidate.confidence,
                reverse=True,
            )
        )

        strongest_candidate = candidates[0] if candidates else None

        heuristic_score = 0
        heuristic_score += min(high_entropy_sections * 20, 40)
        heuristic_score += min(executable_writable_sections * 25, 25)
        heuristic_score += min(suspicious_section_names * 40, 80)

        if len(imports) <= LOW_IMPORT_THRESHOLD:
            heuristic_score += 15

        if overlay_size >= LARGE_OVERLAY_THRESHOLD:
            heuristic_score += 10

        confidence = min(
            100,
            max(
                heuristic_score,
                strongest_candidate.confidence if strongest_candidate else 0,
            ),
        )

        is_likely_packed = confidence >= PACKED_CONFIDENCE_THRESHOLD

        analysis_data = PackerAnalysisData(
            is_likely_packed=is_likely_packed,
            confidence=confidence,
            detected_packer=(strongest_candidate.name if strongest_candidate is not None else None),
            candidates=candidates,
            indicators=tuple(indicators),
            high_entropy_sections=high_entropy_sections,
            executable_writable_sections=executable_writable_sections,
            suspicious_section_names=suspicious_section_names,
            import_count=len(imports),
            overlay_size=overlay_size,
        )

        findings: list[Finding] = []

        if is_likely_packed:
            detected_name = analysis_data.detected_packer or "unknown packer"

            findings.append(
                Finding(
                    title="Executable is likely packed or protected",
                    description=(
                        f"Astra detected multiple packing indicators. "
                        f"Most likely packer: {detected_name}."
                    ),
                    category="packing",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    evidence=tuple(
                        Evidence(
                            kind=indicator.indicator_type,
                            value=indicator.value,
                            location=indicator.location,
                            metadata={
                                "description": indicator.description,
                            },
                        )
                        for indicator in indicators
                    ),
                    tags=("pe", "packing", "obfuscation"),
                    attack_techniques=("T1027",),
                )
            )

        duration_ms = int((time.perf_counter() - start) * 1000)

        return AnalysisResult(
            analyzer=self.name,
            analyzer_version=self.version,
            status=AnalysisStatus.COMPLETED,
            started_at=started_at,
            duration_ms=duration_ms,
            findings=tuple(findings),
            data=analysis_data.model_dump(mode="json"),
        )
