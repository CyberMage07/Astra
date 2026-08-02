"""Indicator-of-compromise extraction for Astra samples."""

from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from analyzers.strings import StringsAnalyzer
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    Evidence,
    Finding,
    IOCAnalysisData,
    IOCIndicator,
    IOCSummary,
    IOCType,
    Severity,
)

URL_PATTERN = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}\b",
    re.IGNORECASE,
)

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

REGISTRY_PATTERN = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|"
    r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|"
    r"HKEY_CURRENT_CONFIG)\\[^\r\n\"']+",
    re.IGNORECASE,
)

WINDOWS_PATH_PATTERN = re.compile(
    r"\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
    r"[^\\/:*?\"<>|\r\n]*",
    re.IGNORECASE,
)

UNC_PATH_PATTERN = re.compile(
    r"\\\\[A-Z0-9._$-]+\\[^\r\n\"']+",
    re.IGNORECASE,
)

POWERSHELL_PATTERN = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)"
    r"\b[^\r\n\"']*",
    re.IGNORECASE,
)

CMD_PATTERN = re.compile(
    r"\bcmd(?:\.exe)?\s+/c\b[^\r\n\"']*",
    re.IGNORECASE,
)

BASE64_PATTERN = re.compile(
    r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
)

IOC_CONFIDENCE: dict[IOCType, int] = {
    IOCType.URL: 90,
    IOCType.DOMAIN: 75,
    IOCType.IPV4: 85,
    IOCType.EMAIL: 80,
    IOCType.REGISTRY_PATH: 85,
    IOCType.WINDOWS_PATH: 70,
    IOCType.UNC_PATH: 85,
    IOCType.POWERSHELL: 90,
    IOCType.CMD: 90,
    IOCType.BASE64: 60,
}

FILE_LIKE_SUFFIXES = {
    "bin",
    "cab",
    "dat",
    "dll",
    "dylib",
    "elf",
    "exe",
    "ini",
    "jar",
    "js",
    "json",
    "log",
    "ocx",
    "pdb",
    "ps1",
    "so",
    "sys",
    "tmp",
    "xml",
}

COMMON_TLDS = {
    "app",
    "biz",
    "cloud",
    "co",
    "com",
    "dev",
    "edu",
    "fr",
    "gov",
    "info",
    "io",
    "me",
    "mil",
    "net",
    "online",
    "org",
    "ru",
    "site",
    "store",
    "tech",
    "top",
    "uk",
    "xyz",
}


def _valid_ipv4(value: str) -> bool:
    """Return whether a string is a valid IPv4 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return isinstance(address, ipaddress.IPv4Address)


def _valid_standalone_ipv4(
    value: str,
    source_string: str,
) -> bool:
    """Reject version-like IPv4 values while preserving network indicators."""
    if not _valid_ipv4(value):
        return False

    address = ipaddress.IPv4Address(value)

    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_reserved:
        return False

    network_context = re.search(
        r"(?:https?://|ftp://|connect|socket|server|host|remote|ip\b)",
        source_string,
        re.IGNORECASE,
    )

    return not (value.endswith(".0") and network_context is None)

    return True


def _valid_domain(
    value: str,
    source_string: str,
) -> bool:
    """Reject file names and weak random strings posing as domains."""
    normalized = value.lower().rstrip(".")
    labels = normalized.split(".")

    if len(labels) < 2:
        return False

    suffix = labels[-1]

    if suffix in FILE_LIKE_SUFFIXES:
        return False

    embedded_in_url_or_email = "://" in source_string or "@" in source_string

    if not embedded_in_url_or_email and suffix not in COMMON_TLDS:
        return False

    if len(normalized) < 6:
        return False

    if len(labels) == 2 and len(labels[0]) < 2:
        return False

    return not all(len(label) <= 2 for label in labels[:-1])


def _normalize_value(
    indicator_type: IOCType,
    value: str,
) -> str:
    """Normalize extracted IOC values."""
    normalized = value.strip().rstrip(".,;:)]}")

    if indicator_type in {
        IOCType.DOMAIN,
        IOCType.EMAIL,
        IOCType.URL,
    }:
        normalized = normalized.lower()

    return normalized


def _extract_matches(
    source_string: str,
    offset: int | None,
) -> list[IOCIndicator]:
    """Extract IOC matches from one source string."""
    extracted: list[IOCIndicator] = []

    pattern_map: tuple[tuple[IOCType, re.Pattern[str]], ...] = (
        (IOCType.URL, URL_PATTERN),
        (IOCType.EMAIL, EMAIL_PATTERN),
        (IOCType.REGISTRY_PATH, REGISTRY_PATTERN),
        (IOCType.UNC_PATH, UNC_PATH_PATTERN),
        (IOCType.WINDOWS_PATH, WINDOWS_PATH_PATTERN),
        (IOCType.POWERSHELL, POWERSHELL_PATTERN),
        (IOCType.CMD, CMD_PATTERN),
        (IOCType.IPV4, IPV4_PATTERN),
        (IOCType.DOMAIN, DOMAIN_PATTERN),
        (IOCType.BASE64, BASE64_PATTERN),
    )

    for indicator_type, pattern in pattern_map:
        for match in pattern.finditer(source_string):
            value = _normalize_value(
                indicator_type,
                match.group(),
            )

            if indicator_type is IOCType.IPV4 and not _valid_standalone_ipv4(
                value,
                source_string,
            ):
                continue

            if indicator_type is IOCType.DOMAIN and not _valid_domain(
                value,
                source_string,
            ):
                continue

            extracted.append(
                IOCIndicator(
                    indicator_type=indicator_type,
                    value=value,
                    source_string=source_string,
                    offset=(offset + match.start() if offset is not None else None),
                    confidence=IOC_CONFIDENCE[indicator_type],
                    tags=("ioc", indicator_type.value),
                )
            )

    return extracted


def _deduplicate(
    indicators: list[IOCIndicator],
) -> tuple[IOCIndicator, ...]:
    """Deduplicate indicators by type and normalized value."""
    unique: dict[tuple[IOCType, str], IOCIndicator] = {}

    for indicator in indicators:
        key = (
            indicator.indicator_type,
            indicator.value,
        )

        existing = unique.get(key)

        if existing is None:
            unique[key] = indicator
            continue

        if indicator.confidence > existing.confidence:
            unique[key] = indicator

    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.indicator_type.value,
                item.value,
            ),
        )
    )


def _build_summaries(
    indicators: tuple[IOCIndicator, ...],
) -> tuple[IOCSummary, ...]:
    """Group extracted indicators by IOC type."""
    grouped: dict[IOCType, list[IOCIndicator]] = defaultdict(list)

    for indicator in indicators:
        grouped[indicator.indicator_type].append(indicator)

    return tuple(
        IOCSummary(
            indicator_type=indicator_type,
            count=len(grouped_indicators),
            indicators=tuple(grouped_indicators),
        )
        for indicator_type, grouped_indicators in sorted(
            grouped.items(),
            key=lambda item: item[0].value,
        )
    )


def _build_findings(
    indicators: tuple[IOCIndicator, ...],
) -> tuple[Finding, ...]:
    """Create concise findings from extracted IOCs."""
    if not indicators:
        return ()

    high_value_types = {
        IOCType.URL,
        IOCType.IPV4,
        IOCType.POWERSHELL,
        IOCType.CMD,
        IOCType.UNC_PATH,
        IOCType.REGISTRY_PATH,
    }

    high_value = tuple(
        indicator for indicator in indicators if indicator.indicator_type in high_value_types
    )

    if not high_value:
        return ()

    representative = high_value[:20]

    return (
        Finding(
            title="Actionable indicators of compromise detected",
            description=(
                f"Astra extracted {len(high_value)} high-value IOC entries "
                "from readable sample content."
            ),
            category="ioc",
            severity=Severity.MEDIUM,
            confidence=80,
            evidence=tuple(
                Evidence(
                    kind=indicator.indicator_type.value,
                    value=indicator.value,
                    location=(
                        f"offset 0x{indicator.offset:x}" if indicator.offset is not None else None
                    ),
                )
                for indicator in representative
            ),
            tags=("ioc", "static-analysis"),
        ),
    )


class IOCAnalyzer:
    """Extract actionable indicators from sample strings."""

    name = "ioc"
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

    def __init__(
        self,
        *,
        minimum_length: int = 4,
        maximum_strings: int = 10_000,
    ) -> None:
        """Initialize IOC extraction limits."""
        self.strings_analyzer = StringsAnalyzer(
            minimum_length=minimum_length,
            maximum_results=maximum_strings,
        )

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Extract normalized indicators from a sample."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        strings_result = self.strings_analyzer.analyze(sample_path)

        if strings_result.status is not AnalysisStatus.COMPLETED:
            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=strings_result.status,
                started_at=started_at,
                duration_ms=int((time.perf_counter() - start) * 1000),
                errors=strings_result.errors,
            )

        raw_strings = strings_result.data["strings"]
        indicators: list[IOCIndicator] = []

        for raw_string in raw_strings:
            indicators.extend(
                _extract_matches(
                    str(raw_string["value"]),
                    int(raw_string["offset"]),
                )
            )

        unique_indicators = _deduplicate(indicators)
        summaries = _build_summaries(unique_indicators)

        analysis_data = IOCAnalysisData(
            total_indicators=len(indicators),
            unique_indicators=len(unique_indicators),
            summaries=summaries,
            indicators=unique_indicators,
        )

        findings = _build_findings(unique_indicators)

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
