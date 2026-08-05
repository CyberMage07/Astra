"""Tests for Astra PE digital-signature analysis."""

import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.signature import SignatureAnalyzer
from packages.schemas import AnalysisStatus


def _mock_pe(
    *,
    security_offset: int,
    security_size: int,
) -> MagicMock:
    """Create a representative mocked PE object."""
    security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

    directories = [MagicMock(VirtualAddress=0, Size=0) for _ in range(security_index + 1)]

    directories[security_index].VirtualAddress = security_offset
    directories[security_index].Size = security_size

    pe = MagicMock()
    pe.OPTIONAL_HEADER.DATA_DIRECTORY = directories

    return pe


def test_signature_analyzer_contract() -> None:
    """The signature analyzer should satisfy Astra's analyzer protocol."""
    analyzer = SignatureAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pkcs7_ber_fallback_warning_is_suppressed(
    tmp_path: Path,
) -> None:
    """The known DER-to-BER fallback warning should not reach the CLI."""
    sample = tmp_path / "signed.exe"

    certificate_header = (
        (8).to_bytes(4, "little") + (0x0200).to_bytes(2, "little") + (0x0002).to_bytes(2, "little")
    )
    sample.write_bytes(b"MZ" + b"\x00" * 30 + certificate_header)

    pe = _mock_pe(
        security_offset=32,
        security_size=8,
    )

    def _load_with_warning(
        _blob: bytes,
    ) -> list[object]:
        warnings.warn(
            (
                "PKCS#7 certificates could not be parsed as DER, "
                "falling back to parsing as BER. "
                "Error details: ValueError"
            ),
            UserWarning,
            stacklevel=2,
        )
        return []

    with (
        patch(
            "analyzers.signature.analyzer.pefile.PE",
            return_value=pe,
        ),
        patch(
            "analyzers.signature.analyzer.pkcs7.load_der_pkcs7_certificates",
            side_effect=_load_with_warning,
        ),
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        result = SignatureAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert not any("falling back to parsing as BER" in str(item.message) for item in caught)


def test_unsigned_pe_is_reported(
    tmp_path: Path,
) -> None:
    """A PE without a security directory should be reported as unsigned."""
    sample = tmp_path / "unsigned.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        security_offset=0,
        security_size=0,
    )

    with patch(
        "analyzers.signature.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = SignatureAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["status"] == "unsigned"
    assert result.data["signature_present"] is False
    assert result.data["is_signed"] is False
    assert result.data["signer_count"] == 0
    assert any(finding.title == "PE file is unsigned" for finding in result.findings)


def test_present_signature_without_certificates(
    tmp_path: Path,
) -> None:
    """A present signature should remain conservatively unverified."""
    sample = tmp_path / "signed.exe"

    pkcs7_payload = b"test"
    certificate_length = 8 + len(pkcs7_payload)

    certificate_header = (
        certificate_length.to_bytes(4, "little")
        + (0x0200).to_bytes(2, "little")
        + (0x0002).to_bytes(2, "little")
    )

    sample.write_bytes(b"MZ" + b"\x00" * 30 + certificate_header + pkcs7_payload)

    pe = _mock_pe(
        security_offset=32,
        security_size=certificate_length,
    )

    with (
        patch(
            "analyzers.signature.analyzer.pefile.PE",
            return_value=pe,
        ),
        patch(
            "analyzers.signature.analyzer._load_certificates",
            return_value=(),
        ),
    ):
        result = SignatureAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["status"] == "present"
    assert result.data["signature_present"] is True
    assert result.data["is_signed"] is True
    assert result.data["signature_valid"] is None
    assert result.data["trust_verified"] is None
    assert result.data["signer_count"] == 0
    assert result.data["verification_error"] is None


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    result = SignatureAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = SignatureAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.exe")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as samples."""
    analyzer = SignatureAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
