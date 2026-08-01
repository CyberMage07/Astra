"""Common analyzer contracts for Astra."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from packages.schemas import AnalysisResult


@runtime_checkable
class Analyzer(Protocol):
    """Contract implemented by Astra analyzers."""

    name: str
    version: str
    supported_families: frozenset[str]

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the detected file family."""
        ...

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze a sample and return a normalized result."""
        ...
