"""Tests for Astra digital-signature CLI analysis."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import AnalysisResult, AnalysisStatus

runner = CliRunner()


def _signature_result() -> AnalysisResult:
    """Return a representative signature-analysis result."""
    return AnalysisResult(
        analyzer="signature",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "status": "present",
            "is_signed": True,
            "signature_present": True,
            "signature_valid": None,
            "trust_verified": None,
            "signer_count": 1,
            "certificates": [
                {
                    "subject": "CN=AstraSigner",
                    "issuer": "CN=AstraCA",
                    "serial_number": "1234",
                    "thumbprint_sha1": "a" * 40,
                    "thumbprint_sha256": "b" * 64,
                    "valid_from": "2024-01-01T00:00:00Z",
                    "valid_until": "2030-01-01T00:00:00Z",
                    "is_expired": False,
                    "is_self_signed": False,
                }
            ],
            "digest_algorithm": "pkcs7-sha256:test",
            "timestamp_present": False,
            "timestamp": None,
            "verification_error": None,
        },
    )


def test_signature_command_displays_certificates(
    tmp_path: Path,
) -> None:
    """The signature command should display parsed certificates."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "apps.cli.main.SignatureAnalyzer.analyze",
        return_value=_signature_result(),
    ):
        result = runner.invoke(
            app,
            ["signature", str(sample)],
        )

    assert result.exit_code == 0
    assert "Digital Signature Analysis" in result.stdout
    assert "PRESENT" in result.stdout
    assert "CN=AstraSigner" in result.stdout
    assert "CN=AstraCA" in result.stdout
    assert "Unknown" in result.stdout


def test_signature_command_handles_unsigned_file(
    tmp_path: Path,
) -> None:
    """The signature command should report unsigned PE files."""
    sample = tmp_path / "unsigned.exe"
    sample.write_bytes(b"MZ")

    unsigned = AnalysisResult(
        analyzer="signature",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=1,
        data={
            "status": "unsigned",
            "is_signed": False,
            "signature_present": False,
            "signature_valid": None,
            "trust_verified": None,
            "signer_count": 0,
            "certificates": [],
            "digest_algorithm": None,
            "timestamp_present": False,
            "timestamp": None,
            "verification_error": None,
        },
    )

    with patch(
        "apps.cli.main.SignatureAnalyzer.analyze",
        return_value=unsigned,
    ):
        result = runner.invoke(
            app,
            ["signature", str(sample)],
        )

    assert result.exit_code == 0
    assert "UNSIGNED" in result.stdout
    assert "The PE file is unsigned" in result.stdout


def test_signature_command_handles_failure(
    tmp_path: Path,
) -> None:
    """The signature command should exit cleanly on failure."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    failed = AnalysisResult(
        analyzer="signature",
        analyzer_version="0.1.0",
        status=AnalysisStatus.FAILED,
        duration_ms=1,
    )

    with patch(
        "apps.cli.main.SignatureAnalyzer.analyze",
        return_value=failed,
    ):
        result = runner.invoke(
            app,
            ["signature", str(sample)],
        )

    assert result.exit_code == 1
    assert "Signature analysis failed" in result.stdout
