"""YARA rule scanning for Astra."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import yara

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    Evidence,
    Finding,
    Severity,
    YaraRuleMatch,
    YaraStringMatch,
)

RULE_SUFFIXES = {".yar", ".yara"}


def _severity_from_metadata(metadata: dict[str, object]) -> Severity:
    """Map YARA metadata severity into Astra severity."""
    value = str(metadata.get("severity", "medium")).lower()

    try:
        return Severity(value)
    except ValueError:
        return Severity.MEDIUM


def _build_findings(matches: tuple[YaraRuleMatch, ...]) -> tuple[Finding, ...]:
    """Create explainable Astra findings from YARA matches."""
    findings: list[Finding] = []

    for match in matches:
        description = str(
            match.metadata.get(
                "description",
                f"The sample matched the YARA rule {match.rule}.",
            )
        )
        category = str(match.metadata.get("category", "yara-match"))
        severity = _severity_from_metadata(match.metadata)

        evidence = tuple(
            Evidence(
                kind="yara-string",
                value=string_match.matched_data,
                location=f"offset 0x{string_match.offset:x}",
                metadata={"identifier": string_match.identifier},
            )
            for string_match in match.strings
        )

        findings.append(
            Finding(
                title=f"YARA rule matched: {match.rule}",
                description=description,
                category=category,
                severity=severity,
                confidence=90,
                evidence=evidence,
                tags=("yara", match.namespace, *match.tags),
            )
        )

    return tuple(findings)


class YaraAnalyzer:
    """Analyze files using compiled YARA rules."""

    name = "yara"
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
            "unknown",
        }
    )

    def __init__(self, rules_root: Path) -> None:
        """Initialize the analyzer with a YARA rule directory."""
        self.rules_root = rules_root.expanduser().resolve()

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def _discover_rules(self) -> dict[str, str]:
        """Discover YARA rule files and map them to namespaces."""
        if not self.rules_root.exists():
            raise FileNotFoundError(self.rules_root)

        if not self.rules_root.is_dir():
            raise ValueError(f"Rules root is not a directory: {self.rules_root}")

        discovered: dict[str, str] = {}

        for rule_path in sorted(self.rules_root.rglob("*")):
            if not rule_path.is_file():
                continue

            if rule_path.suffix.lower() not in RULE_SUFFIXES:
                continue

            relative_path = rule_path.relative_to(self.rules_root)
            namespace = "_".join(relative_path.with_suffix("").parts)
            discovered[namespace] = str(rule_path)

        return discovered

    def _compile_rules(self) -> yara.Rules:
        """Compile all discovered YARA rule files."""
        discovered = self._discover_rules()

        if not discovered:
            raise ValueError(f"No YARA rules found under {self.rules_root}")

        return yara.compile(filepaths=discovered)

    @staticmethod
    def _normalize_matches(matches: list[yara.Match]) -> tuple[YaraRuleMatch, ...]:
        """Normalize yara-python matches into Astra schemas."""
        normalized: list[YaraRuleMatch] = []

        for match in matches:
            string_matches: list[YaraStringMatch] = []

            for matched_string in match.strings:
                for instance in matched_string.instances:
                    matched_data = bytes(instance.matched_data).decode(
                        "utf-8",
                        errors="replace",
                    )

                    string_matches.append(
                        YaraStringMatch(
                            identifier=matched_string.identifier,
                            offset=int(instance.offset),
                            matched_data=matched_data,
                        )
                    )

            normalized.append(
                YaraRuleMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=tuple(match.tags),
                    metadata=dict(match.meta),
                    strings=tuple(string_matches),
                )
            )

        return tuple(normalized)

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Scan a sample using Astra YARA rules."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        resolved_path = sample_path.expanduser().resolve()

        if not resolved_path.exists():
            raise FileNotFoundError(resolved_path)

        if not resolved_path.is_file():
            raise ValueError(f"Path is not a regular file: {resolved_path}")

        try:
            rules = self._compile_rules()
            matches = rules.match(str(resolved_path))
            normalized_matches = self._normalize_matches(matches)
            findings = _build_findings(normalized_matches)
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.COMPLETED,
                started_at=started_at,
                duration_ms=duration_ms,
                findings=findings,
                data={
                    "rules_root": str(self.rules_root),
                    "match_count": len(normalized_matches),
                    "matches": [match.model_dump(mode="json") for match in normalized_matches],
                },
            )

        except yara.SyntaxError as error:
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

        except yara.Error as error:
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
