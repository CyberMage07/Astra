"""Tests for Astra threat scoring."""

from packages.schemas import Finding, Severity, ThreatClassification
from rules.scoring import assess_findings


def test_no_findings_are_likely_benign() -> None:
    """An empty finding set should produce the lowest classification."""
    assessment = assess_findings(())

    assert assessment.score == 0
    assert assessment.classification is ThreatClassification.LIKELY_BENIGN
    assert assessment.confidence == 50
    assert assessment.reasons == ()
    assert assessment.attack_techniques == ()


def test_low_risk_findings_are_scored() -> None:
    """Moderate evidence should produce a low-risk assessment."""
    findings = (
        Finding(
            title="Registry modification",
            description="Writes a registry value.",
            category="registry-modification",
            severity=Severity.MEDIUM,
            confidence=50,
            attack_techniques=("T1112",),
        ),
        Finding(
            title="File deletion",
            description="Deletes a file.",
            category="file-manipulation",
            severity=Severity.LOW,
            confidence=30,
            attack_techniques=("T1070.004",),
        ),
    )

    assessment = assess_findings(findings)

    assert 0 < assessment.score <= 40
    assert assessment.classification in {
        ThreatClassification.LIKELY_BENIGN,
        ThreatClassification.LOW_RISK,
    }
    assert assessment.attack_techniques == ("T1070.004", "T1112")
    assert assessment.reasons


def test_high_severity_diverse_findings_raise_score() -> None:
    """Strong evidence across categories should produce a high-risk result."""
    findings = (
        Finding(
            title="Process injection",
            description="Remote thread creation detected.",
            category="process-injection",
            severity=Severity.HIGH,
            confidence=95,
            attack_techniques=("T1055",),
        ),
        Finding(
            title="Known ransomware rule matched",
            description="YARA matched a ransomware family.",
            category="yara",
            severity=Severity.CRITICAL,
            confidence=98,
            attack_techniques=("T1486",),
        ),
        Finding(
            title="Packed executable",
            description="The executable is packed.",
            category="packing",
            severity=Severity.HIGH,
            confidence=90,
            attack_techniques=("T1027",),
        ),
    )

    assessment = assess_findings(findings)

    assert assessment.score >= 61
    assert assessment.classification in {
        ThreatClassification.HIGH_RISK,
        ThreatClassification.HIGHLY_SUSPICIOUS,
    }
    assert assessment.confidence >= 80
    assert set(assessment.attack_techniques) == {
        "T1027",
        "T1055",
        "T1486",
    }


def test_duplicate_findings_do_not_inflate_score() -> None:
    """Duplicate findings should be deduplicated before scoring."""
    weaker = Finding(
        title="Suspicious API",
        description="Representative finding.",
        category="imports",
        severity=Severity.MEDIUM,
        confidence=40,
    )
    stronger = Finding(
        title="Suspicious API",
        description="Representative finding.",
        category="imports",
        severity=Severity.HIGH,
        confidence=90,
    )

    duplicate_assessment = assess_findings((weaker, stronger))
    single_assessment = assess_findings((stronger,))

    assert duplicate_assessment.score == single_assessment.score
    assert duplicate_assessment.reasons == single_assessment.reasons


def test_reason_count_is_limited() -> None:
    """The assessment should keep only the strongest reasons."""
    findings = tuple(
        Finding(
            title=f"Finding {index}",
            description="Representative finding.",
            category=f"category-{index}",
            severity=Severity.MEDIUM,
            confidence=80,
        )
        for index in range(20)
    )

    assessment = assess_findings(findings)

    assert len(assessment.reasons) == 8
