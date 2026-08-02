"""Suspicious Windows API import profiling."""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from analyzers.pe import PEAnalyzer
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    Evidence,
    Finding,
    ImportAnalysisData,
    ImportBehaviorSummary,
    ImportIndicator,
    Severity,
)

API_RULES: dict[str, tuple[str, str, Severity, int, tuple[str, ...]]] = {
    "CreateRemoteThread": (
        "process-injection",
        "Creates a thread in another process.",
        Severity.HIGH,
        90,
        ("T1055",),
    ),
    "WriteProcessMemory": (
        "process-injection",
        "Writes data into another process.",
        Severity.HIGH,
        90,
        ("T1055",),
    ),
    "VirtualAllocEx": (
        "process-injection",
        "Allocates memory in another process.",
        Severity.HIGH,
        85,
        ("T1055",),
    ),
    "OpenProcess": (
        "process-access",
        "Opens a handle to another process.",
        Severity.MEDIUM,
        55,
        ("T1055",),
    ),
    "IsDebuggerPresent": (
        "anti-analysis",
        "Checks whether the process is being debugged.",
        Severity.MEDIUM,
        60,
        ("T1622",),
    ),
    "CheckRemoteDebuggerPresent": (
        "anti-analysis",
        "Checks for a remote debugger.",
        Severity.MEDIUM,
        65,
        ("T1622",),
    ),
    "CryptEncrypt": (
        "cryptography",
        "Encrypts data using the Windows CryptoAPI.",
        Severity.MEDIUM,
        60,
        ("T1486",),
    ),
    "CryptDecrypt": (
        "cryptography",
        "Decrypts data using the Windows CryptoAPI.",
        Severity.LOW,
        35,
        (),
    ),
    "CreateServiceA": (
        "persistence",
        "Creates a Windows service.",
        Severity.HIGH,
        80,
        ("T1543.003",),
    ),
    "CreateServiceW": (
        "persistence",
        "Creates a Windows service.",
        Severity.HIGH,
        80,
        ("T1543.003",),
    ),
    "RegSetValueExA": (
        "registry-modification",
        "Writes a Windows Registry value.",
        Severity.MEDIUM,
        50,
        ("T1112",),
    ),
    "RegSetValueExW": (
        "registry-modification",
        "Writes a Windows Registry value.",
        Severity.MEDIUM,
        50,
        ("T1112",),
    ),
    "URLDownloadToFileA": (
        "payload-download",
        "Downloads a remote file.",
        Severity.HIGH,
        80,
        ("T1105",),
    ),
    "URLDownloadToFileW": (
        "payload-download",
        "Downloads a remote file.",
        Severity.HIGH,
        80,
        ("T1105",),
    ),
    "InternetOpenUrlA": (
        "network-access",
        "Opens a remote resource using WinINet.",
        Severity.MEDIUM,
        55,
        ("T1071.001",),
    ),
    "InternetOpenUrlW": (
        "network-access",
        "Opens a remote resource using WinINet.",
        Severity.MEDIUM,
        55,
        ("T1071.001",),
    ),
    "DeleteFileA": (
        "file-manipulation",
        "Deletes a file.",
        Severity.LOW,
        30,
        ("T1070.004",),
    ),
    "DeleteFileW": (
        "file-manipulation",
        "Deletes a file.",
        Severity.LOW,
        30,
        ("T1070.004",),
    ),
}

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ImportAnalyzer:
    """Classify suspicious PE imports into analyst-friendly behaviors."""

    name = "imports"
    version = "0.1.0"
    supported_families = frozenset({"pe"})

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Analyze suspicious PE imports."""
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

        imports = pe_result.data["imports"]
        indicators: list[ImportIndicator] = []

        for imported in imports:
            function = str(imported["function"])
            rule = API_RULES.get(function)

            if rule is None:
                continue

            category, description, severity, weight, techniques = rule

            indicators.append(
                ImportIndicator(
                    library=str(imported["library"]),
                    function=function,
                    category=category,
                    description=description,
                    severity=severity,
                    weight=weight,
                    attack_techniques=techniques,
                )
            )

        grouped: dict[str, list[ImportIndicator]] = defaultdict(list)

        for indicator in indicators:
            grouped[indicator.category].append(indicator)

        behaviors: list[ImportBehaviorSummary] = []

        for category, category_indicators in sorted(grouped.items()):
            maximum_severity = max(
                (indicator.severity for indicator in category_indicators),
                key=SEVERITY_ORDER.__getitem__,
            )

            behaviors.append(
                ImportBehaviorSummary(
                    category=category,
                    count=len(category_indicators),
                    maximum_severity=maximum_severity,
                    indicators=tuple(category_indicators),
                )
            )

        data = ImportAnalysisData(
            total_imports=len(imports),
            suspicious_imports=len(indicators),
            behaviors=tuple(behaviors),
            indicators=tuple(indicators),
        )

        findings = tuple(
            Finding(
                title=f"Suspicious imported API: {indicator.function}",
                description=indicator.description,
                category=indicator.category,
                severity=indicator.severity,
                confidence=indicator.weight,
                evidence=(
                    Evidence(
                        kind="pe-import",
                        value=indicator.function,
                        location=indicator.library,
                    ),
                ),
                tags=("pe", "imports", indicator.category),
                attack_techniques=indicator.attack_techniques,
            )
            for indicator in indicators
        )

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
