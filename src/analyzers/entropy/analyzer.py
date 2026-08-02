"""Entropy analysis for binary samples."""

from __future__ import annotations

import math
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    EntropyAnalysisData,
    EntropyRegion,
    Evidence,
    Finding,
    Severity,
)

DEFAULT_BLOCK_SIZE = 4096
HIGH_ENTROPY_THRESHOLD = 7.2


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0

    frequencies = Counter(data)
    data_length = len(data)

    return -sum(
        (count / data_length) * math.log2(count / data_length) for count in frequencies.values()
    )


def _analyze_regions(
    data: bytes,
    block_size: int,
) -> tuple[EntropyRegion, ...]:
    """Calculate entropy for fixed-size regions."""
    regions: list[EntropyRegion] = []

    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]

        regions.append(
            EntropyRegion(
                offset=offset,
                size=len(block),
                entropy=calculate_entropy(block),
            )
        )

    return tuple(regions)


def _build_findings(data: EntropyAnalysisData) -> tuple[Finding, ...]:
    """Generate concise, explainable findings from entropy measurements."""
    findings: list[Finding] = []

    high_entropy_regions = tuple(
        region for region in data.regions if region.entropy >= HIGH_ENTROPY_THRESHOLD
    )

    if data.overall_entropy >= HIGH_ENTROPY_THRESHOLD:
        findings.append(
            Finding(
                title="High overall file entropy",
                description=(
                    "The file has high overall entropy, which may indicate "
                    "compression, encryption, packing, or dense binary data."
                ),
                category="entropy",
                severity=Severity.MEDIUM,
                confidence=70,
                evidence=(
                    Evidence(
                        kind="overall-entropy",
                        value=f"{data.overall_entropy:.2f}",
                        location="entire file",
                    ),
                ),
                tags=("entropy", "packing"),
            )
        )

    if high_entropy_regions:
        representative_regions = sorted(
            high_entropy_regions,
            key=lambda region: region.entropy,
            reverse=True,
        )[:10]

        findings.append(
            Finding(
                title="High-entropy regions detected",
                description=(
                    f"Astra detected {len(high_entropy_regions)} high-entropy "
                    "regions. These regions may contain compressed, encrypted, "
                    "packed, or embedded content."
                ),
                category="entropy-region",
                severity=Severity.MEDIUM,
                confidence=65,
                evidence=tuple(
                    Evidence(
                        kind="region-entropy",
                        value=f"{region.entropy:.2f}",
                        location=f"offset 0x{region.offset:x}",
                        metadata={"size": region.size},
                    )
                    for region in representative_regions
                ),
                tags=("entropy", "region"),
            )
        )

    return tuple(findings)


class EntropyAnalyzer:
    """Analyze whole-file and block-level entropy."""

    name = "entropy"
    version = "0.1.0"
    supported_families = frozenset(
        {
            "pe",
            "elf",
            "mach-o",
            "pdf",
            "office",
            "apk",
            "archive",
            "script",
            "text",
            "image",
            "audio",
            "video",
            "unknown",
        }
    )

    def __init__(self, block_size: int = DEFAULT_BLOCK_SIZE) -> None:
        """Initialize the analyzer with a block size."""
        if block_size <= 0:
            raise ValueError("block_size must be greater than zero")

        self.block_size = block_size

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze entropy for a sample."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        content = resolved_path.read_bytes()
        regions = _analyze_regions(content, self.block_size)
        overall_entropy = calculate_entropy(content)

        maximum_region_entropy = max(
            (region.entropy for region in regions),
            default=0.0,
        )

        high_entropy_regions = sum(
            1 for region in regions if region.entropy >= HIGH_ENTROPY_THRESHOLD
        )

        analysis_data = EntropyAnalysisData(
            overall_entropy=overall_entropy,
            file_size=len(content),
            block_size=self.block_size,
            regions=regions,
            high_entropy_regions=high_entropy_regions,
            maximum_region_entropy=maximum_region_entropy,
        )

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
