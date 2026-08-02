"""Astra threat scoring rules."""

from rules.scoring.engine import (
    CLASSIFICATION_THRESHOLDS,
    MAX_REASON_COUNT,
    SEVERITY_WEIGHTS,
    assess_findings,
)

__all__ = [
    "CLASSIFICATION_THRESHOLDS",
    "MAX_REASON_COUNT",
    "SEVERITY_WEIGHTS",
    "assess_findings",
]
