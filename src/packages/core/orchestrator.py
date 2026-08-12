"""Unified static-analysis orchestration for Astra."""

from __future__ import annotations

import time
from pathlib import Path

from analyzers.debug import DebugDirectoryAnalyzer
from analyzers.entropy import EntropyAnalyzer
from analyzers.exports import ExportsAnalyzer
from analyzers.filetype import identify_file
from analyzers.hashing import calculate_hashes
from analyzers.importdirectories import ImportDirectoriesAnalyzer
from analyzers.ioc import IOCAnalyzer
from analyzers.loadconfig import LoadConfigAnalyzer
from analyzers.metadata import MetadataAnalyzer
from analyzers.overlay import OverlayAnalyzer
from analyzers.packer import PackerAnalyzer
from analyzers.pe import PEAnalyzer
from analyzers.resources import ResourcesAnalyzer
from analyzers.richheader import RichHeaderAnalyzer
from analyzers.sections import SectionsAnalyzer
from analyzers.signature import SignatureAnalyzer
from analyzers.signatures import ImportAnalyzer
from analyzers.strings import StringsAnalyzer
from analyzers.tls import TLSAnalyzer
from analyzers.versioninfo import VersionInfoAnalyzer
from analyzers.yara import YaraAnalyzer
from packages.schemas import (
    AnalysisReport,
    AnalysisResult,
    AnalysisStatus,
    AnalyzerExecution,
    Finding,
)
from rules.scoring import assess_findings


class AnalysisOrchestrator:
    """Run relevant Astra analyzers and build one unified report."""

    def __init__(
        self,
        rules_root: Path = Path("rules/yara"),
    ) -> None:
        """Initialize the orchestrator."""
        self.rules_root = rules_root.expanduser().resolve()

    def _run_analyzers(
        self,
        sample_path: Path,
        family: str,
    ) -> tuple[AnalysisResult, ...]:
        """Run analyzers relevant to the detected file family."""
        results: list[AnalysisResult] = []

        strings_analyzer = StringsAnalyzer()
        ioc_analyzer = IOCAnalyzer()

        if strings_analyzer.supports(family):
            strings_result = strings_analyzer.analyze(sample_path)
            results.append(strings_result)

            if ioc_analyzer.supports(family):
                results.append(ioc_analyzer.analyze_strings(strings_result))

        general_analyzers = (
            EntropyAnalyzer(),
            YaraAnalyzer(self.rules_root),
        )

        for general_analyzer in general_analyzers:
            if general_analyzer.supports(family):
                results.append(general_analyzer.analyze(sample_path))

        if family == "pe":
            pe_analyzers = (
                PEAnalyzer(),
                SectionsAnalyzer(),
                ResourcesAnalyzer(),
                OverlayAnalyzer(),
                TLSAnalyzer(),
                SignatureAnalyzer(),
                VersionInfoAnalyzer(),
                RichHeaderAnalyzer(),
                DebugDirectoryAnalyzer(),
                LoadConfigAnalyzer(),
                ExportsAnalyzer(),
                ImportDirectoriesAnalyzer(),
                MetadataAnalyzer(),
                ImportAnalyzer(),
                PackerAnalyzer(),
            )

            for pe_analyzer in pe_analyzers:
                results.append(pe_analyzer.analyze(sample_path))

        return tuple(results)

    @staticmethod
    def _build_executions(
        results: tuple[AnalysisResult, ...],
    ) -> tuple[AnalyzerExecution, ...]:
        """Build execution summaries from analyzer results."""
        return tuple(
            AnalyzerExecution(
                analyzer=result.analyzer,
                status=result.status.value,
                duration_ms=result.duration_ms,
                finding_count=len(result.findings),
                error_count=len(result.errors),
            )
            for result in results
        )

    @staticmethod
    def _collect_findings(
        results: tuple[AnalysisResult, ...],
    ) -> tuple[Finding, ...]:
        """Collect findings from all analyzer results."""
        return tuple(finding for result in results for finding in result.findings)

    def analyze(
        self,
        sample_path: Path,
    ) -> AnalysisReport:
        """Run Astra's unified static-analysis pipeline."""
        start = time.perf_counter()
        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        file_type = identify_file(resolved_path)
        hashes = calculate_hashes(resolved_path)

        analyzer_results = self._run_analyzers(
            resolved_path,
            file_type.detected_family,
        )

        executions = self._build_executions(analyzer_results)
        findings = self._collect_findings(analyzer_results)
        assessment = assess_findings(findings)

        completed_analyzers = sum(
            1 for result in analyzer_results if result.status is AnalysisStatus.COMPLETED
        )

        failed_analyzers = sum(
            1
            for result in analyzer_results
            if result.status
            in {
                AnalysisStatus.FAILED,
                AnalysisStatus.PARTIAL,
            }
        )

        total_duration_ms = int((time.perf_counter() - start) * 1000)

        return AnalysisReport(
            sample_path=resolved_path,
            original_name=resolved_path.name,
            size_bytes=resolved_path.stat().st_size,
            hashes=hashes,
            file_type=file_type,
            analyzer_results=analyzer_results,
            analyzer_executions=executions,
            findings=findings,
            assessment=assessment,
            completed_analyzers=completed_analyzers,
            failed_analyzers=failed_analyzers,
            total_duration_ms=total_duration_ms,
        )
