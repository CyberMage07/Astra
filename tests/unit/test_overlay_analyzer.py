"""Tests for Astra PE overlay analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.overlay import OverlayAnalyzer
from packages.schemas import AnalysisStatus


def _mock_pe(
    *,
    overlay_offset: int | None,
) -> MagicMock:
    """Create a representative mocked PE object."""
    pe = MagicMock()
    pe.get_overlay_data_start_offset.return_value = overlay_offset

    return pe


def _certificate_table_payload() -> bytes:
    """Return a representative WIN_CERTIFICATE structure."""
    pkcs7_payload = b"\x30\x82" + b"A" * 22
    certificate_length = 8 + len(pkcs7_payload)

    header = (
        certificate_length.to_bytes(
            4,
            byteorder="little",
        )
        + (0x0200).to_bytes(
            2,
            byteorder="little",
        )
        + (0x0002).to_bytes(
            2,
            byteorder="little",
        )
    )

    return header + pkcs7_payload


def test_overlay_analyzer_contract() -> None:
    """The overlay analyzer should satisfy Astra's analyzer protocol."""
    analyzer = OverlayAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_overlay_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without appended data should return an empty result."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 30)

    pe = _mock_pe(
        overlay_offset=None,
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is False
    assert result.data["offset"] is None
    assert result.data["size"] == 0
    assert result.data["sha256"] is None
    assert result.data["embedded_file_type"] is None
    assert result.data["is_executable"] is False
    assert result.data["is_archive"] is False
    assert result.data["is_document"] is False
    assert result.data["is_script"] is False
    assert result.data["is_certificate_table"] is False
    assert result.data["is_installer_payload"] is False
    assert result.data["installer_type"] is None
    assert result.findings == ()


def test_embedded_pe_overlay_generates_finding(
    tmp_path: Path,
) -> None:
    """An executable stored in the overlay should generate a finding."""
    sample = tmp_path / "embedded-pe.exe"

    base_data = b"MZ" + b"\x00" * 30
    overlay_data = b"MZ" + b"\x90" * 126

    sample.write_bytes(base_data + overlay_data)

    pe = _mock_pe(
        overlay_offset=len(base_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is True
    assert result.data["offset"] == len(base_data)
    assert result.data["size"] == len(overlay_data)
    assert result.data["embedded_file_type"] == "pe"
    assert result.data["is_executable"] is True
    assert result.data["is_archive"] is False
    assert result.data["is_certificate_table"] is False
    assert result.data["is_installer_payload"] is False

    assert any(
        finding.title == "Executable payload detected in PE overlay" for finding in result.findings
    )


def test_embedded_zip_overlay_generates_finding(
    tmp_path: Path,
) -> None:
    """An archive stored in the overlay should generate a finding."""
    sample = tmp_path / "embedded-zip.exe"

    base_data = b"MZ" + b"\x00" * 30
    overlay_data = b"PK\x03\x04" + b"\x00" * 124

    sample.write_bytes(base_data + overlay_data)

    pe = _mock_pe(
        overlay_offset=len(base_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["embedded_file_type"] == "zip"
    assert result.data["is_archive"] is True
    assert result.data["is_executable"] is False

    assert any(
        finding.title == "Archive payload detected in PE overlay" for finding in result.findings
    )


def test_high_entropy_unknown_overlay_generates_finding(
    tmp_path: Path,
) -> None:
    """Unrecognized high-entropy overlay data should be reported."""
    sample = tmp_path / "high-entropy.exe"

    base_data = b"MZ" + b"\x00" * 30
    overlay_data = bytes(range(256)) * 8

    sample.write_bytes(base_data + overlay_data)

    pe = _mock_pe(
        overlay_offset=len(base_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is True
    assert result.data["embedded_file_type"] is None
    assert result.data["is_high_entropy"] is True
    assert result.data["is_certificate_table"] is False
    assert result.data["is_installer_payload"] is False

    assert any(finding.title == "High-entropy PE overlay detected" for finding in result.findings)


def test_nsis_installer_overlay_is_suppressed(
    tmp_path: Path,
) -> None:
    """Recognized NSIS payloads should not produce overlay findings."""
    sample = tmp_path / "installer.exe"

    base_data = b"MZ" + b"\x00" * 30
    overlay_data = b"\x00\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst" + bytes(range(256)) * 32

    sample.write_bytes(base_data + overlay_data)

    pe = _mock_pe(
        overlay_offset=len(base_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is True
    assert result.data["is_installer_payload"] is True
    assert result.data["installer_type"] == "nsis"
    assert result.data["is_certificate_table"] is False
    assert result.findings == ()


def test_certificate_table_overlay_is_suppressed(
    tmp_path: Path,
) -> None:
    """Authenticode certificate-table data should not be suspicious."""
    sample = tmp_path / "signed.exe"

    base_data = b"MZ" + b"\x00" * 30
    overlay_data = _certificate_table_payload()

    sample.write_bytes(base_data + overlay_data)

    pe = _mock_pe(
        overlay_offset=len(base_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is True
    assert result.data["is_certificate_table"] is True
    assert result.data["is_installer_payload"] is False
    assert result.data["installer_type"] is None
    assert result.findings == ()


def test_overlay_offset_at_end_returns_empty_result(
    tmp_path: Path,
) -> None:
    """An offset at the end of the file should not create an overlay."""
    sample = tmp_path / "empty-overlay.exe"
    sample_data = b"MZ" + b"\x00" * 30
    sample.write_bytes(sample_data)

    pe = _mock_pe(
        overlay_offset=len(sample_data),
    )

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["overlay_present"] is False
    assert result.data["size"] == 0
    assert result.findings == ()


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.overlay.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = OverlayAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = OverlayAnalyzer()

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
    analyzer = OverlayAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
