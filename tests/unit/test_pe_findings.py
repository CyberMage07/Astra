"""Tests for Astra PE security findings."""

from analyzers.pe.analyzer import _build_findings
from packages.schemas import (
    PEAnalysisData,
    PEHeaderInfo,
    PEImport,
    PESection,
    Severity,
)


def _header() -> PEHeaderInfo:
    """Return a minimal valid PE header."""
    return PEHeaderInfo(
        machine="x86-64",
        architecture_bits=64,
        subsystem="Windows GUI",
        image_base=0x400000,
        entry_point=0x1000,
        compile_timestamp=1700000000,
        number_of_sections=1,
        characteristics=0x22,
        is_dll=False,
        is_driver=False,
    )


def test_suspicious_import_creates_finding() -> None:
    """Known suspicious APIs should produce explainable findings."""
    data = PEAnalysisData(
        header=_header(),
        imports=(
            PEImport(
                library="KERNEL32.dll",
                function="CreateRemoteThread",
                address=0x2000,
            ),
        ),
    )

    findings = _build_findings(data)

    assert len(findings) == 1
    assert findings[0].category == "process-injection"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence[0].value == "CreateRemoteThread"


def test_high_entropy_section_creates_finding() -> None:
    """High-entropy sections should produce packing findings."""
    data = PEAnalysisData(
        header=_header(),
        sections=(
            PESection(
                name=".packed",
                virtual_address=0x1000,
                virtual_size=4096,
                raw_size=4096,
                entropy=7.85,
                characteristics=0x40000040,
                executable=False,
                writable=False,
                readable=True,
            ),
        ),
    )

    findings = _build_findings(data)

    assert any(finding.category == "packing" for finding in findings)


def test_rwx_section_creates_high_severity_finding() -> None:
    """Writable and executable sections should be flagged."""
    data = PEAnalysisData(
        header=_header(),
        sections=(
            PESection(
                name=".evil",
                virtual_address=0x1000,
                virtual_size=4096,
                raw_size=4096,
                entropy=6.0,
                characteristics=0xE0000020,
                executable=True,
                writable=True,
                readable=True,
            ),
        ),
    )

    findings = _build_findings(data)

    assert any(
        finding.category == "memory-protection" and finding.severity is Severity.HIGH
        for finding in findings
    )


def test_tls_callbacks_create_finding() -> None:
    """TLS callbacks should produce an execution-flow finding."""
    data = PEAnalysisData(
        header=_header(),
        has_tls_callbacks=True,
    )

    findings = _build_findings(data)

    assert any(finding.category == "execution-flow" for finding in findings)
