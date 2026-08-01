"""Tests for Astra CLI commands."""

from typer.testing import CliRunner

from apps.cli.main import app

runner = CliRunner()


def test_version_command() -> None:
    """The version command should return Astra version information."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "Astra" in result.stdout
    assert "0.1.0" in result.stdout


def test_banner_command() -> None:
    """The banner command should display Astra branding."""
    result = runner.invoke(app, ["banner"])

    assert result.exit_code == 0
    assert "ASTRA" in result.stdout
    assert "Malware Analysis Platform" in result.stdout


def test_doctor_command() -> None:
    """The doctor command should report successful required checks."""
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Astra Environment Check" in result.stdout
    assert "All required Astra checks passed" in result.stdout
