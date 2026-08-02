"""Astra PE packer detection analyzer."""

from analyzers.packer.analyzer import (
    HIGH_ENTROPY_THRESHOLD,
    KNOWN_PACKER_SECTIONS,
    LARGE_OVERLAY_THRESHOLD,
    LOW_IMPORT_THRESHOLD,
    PACKED_CONFIDENCE_THRESHOLD,
    PackerAnalyzer,
)

__all__ = [
    "HIGH_ENTROPY_THRESHOLD",
    "KNOWN_PACKER_SECTIONS",
    "LARGE_OVERLAY_THRESHOLD",
    "LOW_IMPORT_THRESHOLD",
    "PACKED_CONFIDENCE_THRESHOLD",
    "PackerAnalyzer",
]
