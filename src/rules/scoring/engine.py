"""Threat scoring and classification for Astra analysis reports."""

from __future__ import annotations

from collections import Counter

from packages.schemas import (
    Finding,
    Severity,
    ThreatAssessment,
    ThreatClassification,
)

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 5,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

CLASSIFICATION_THRESHOLDS: tuple[tuple[int, ThreatClassification], ...] = (
    (81, ThreatClassification.HIGHLY_SUSPICIOUS),
    (61, ThreatClassification.HIGH_RISK),
    (41, ThreatClassification.SUSPICIOUS),
    (21, ThreatClassification.LOW_RISK),
    (0, ThreatClassification.LIKELY_BENIGN),
)

MAX_REASON_COUNT = 8


def _finding_score(finding: Finding) -> int:
    """Calculate the weighted contribution of one finding."""
    severity_weight = SEVERITY_WEIGHTS[finding.severity]
    confidence_factor = finding.confidence / 100

    return round(severity_weight * confidence_factor)


def _classification_for_score(score: int) -> ThreatClassification:
    """Map a numeric risk score to a threat classification."""
    for threshold, classification in CLASSIFICATION_THRESHOLDS:
        if score >= threshold:
            return classification

    return ThreatClassification.LIKELY_BENIGN


def _deduplicate_findings(
    findings: tuple[Finding, ...],
) -> tuple[Finding, ...]:
    """Remove duplicate findings while preserving the strongest instance."""
    strongest: dict[tuple[str, str], Finding] = {}

    for finding in findings:
        key = (finding.category, finding.title)
        existing = strongest.get(key)

        if existing is None:
            strongest[key] = finding
            continue

        existing_score = _finding_score(existing)
        candidate_score = _finding_score(finding)

        if candidate_score > existing_score:
            strongest[key] = finding

    return tuple(strongest.values())


def _build_reasons(
    findings: tuple[Finding, ...],
) -> tuple[str, ...]:
    """Build concise analyst-facing reasons for the assessment."""
    ranked = sorted(
        findings,
        key=lambda finding: (
            _finding_score(finding),
            finding.confidence,
            SEVERITY_WEIGHTS[finding.severity],
        ),
        reverse=True,
    )

    return tuple(
        f"{finding.severity.value.upper()}: {finding.title}"
        for finding in ranked[:MAX_REASON_COUNT]
    )


def _collect_attack_techniques(
    findings: tuple[Finding, ...],
) -> tuple[str, ...]:
    """Collect unique MITRE ATT&CK techniques from findings."""
    return tuple(
        sorted({technique for finding in findings for technique in finding.attack_techniques})
    )


def _calculate_confidence(
    findings: tuple[Finding, ...],
    score: int,
) -> int:
    """Estimate confidence in the aggregated threat assessment."""
    if not findings:
        return 50

    average_finding_confidence = round(
        sum(finding.confidence for finding in findings) / len(findings)
    )

    evidence_bonus = min(len(findings) * 3, 15)
    technique_bonus = min(
        len(_collect_attack_techniques(findings)) * 2,
        10,
    )

    return min(
        100,
        round(average_finding_confidence * 0.7 + score * 0.2 + evidence_bonus + technique_bonus),
    )


def assess_findings(
    findings: tuple[Finding, ...],
) -> ThreatAssessment:
    """Create a normalized threat assessment from analyzer findings."""
    unique_findings = _deduplicate_findings(findings)

    raw_score = sum(_finding_score(finding) for finding in unique_findings)

    category_counts = Counter(finding.category for finding in unique_findings)

    category_diversity_bonus = min(
        max(len(category_counts) - 1, 0) * 4,
        16,
    )

    high_severity_bonus = min(
        sum(
            6
            for finding in unique_findings
            if finding.severity
            in {
                Severity.HIGH,
                Severity.CRITICAL,
            }
        ),
        18,
    )

    score = min(
        100,
        raw_score + category_diversity_bonus + high_severity_bonus,
    )

    classification = _classification_for_score(score)
    confidence = _calculate_confidence(
        unique_findings,
        score,
    )

    return ThreatAssessment(
        score=score,
        classification=classification,
        confidence=confidence,
        reasons=_build_reasons(unique_findings),
        attack_techniques=_collect_attack_techniques(unique_findings),
    )
