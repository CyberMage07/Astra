"""Tests for Astra CLI file identification."""

from pathlib import Path

from typer.testing import CliRunner

from apps.cli.main import app

runner = CliRunner()


def test_identify_text_file(tmp_path: Path) -> None:
    """The identify command should display content-based file information."""
    sample = tmp_path / "notes.txt"
    sample.write_text("Astra identification test\n", encoding="utf-8")

    result = runner.invoke(app, ["identify", str(sample)])

    assert result.exit_code == 0
    assert "File Identification" in result.stdout
    assert "notes.txt" in result.stdout
    assert "text" in result.stdout
    assert "text/plain" in result.stdout
    assert "Match" in result.stdout


def test_identify_extension_mismatch(tmp_path: Path) -> None:
    """The identify command should reveal misleading extensions."""
    sample = tmp_path / "document.pdf"
    sample.write_text("This is plain text.", encoding="utf-8")

    result = runner.invoke(app, ["identify", str(sample)])

    assert result.exit_code == 0
    assert "Mismatch" in result.stdout
    assert "text" in result.stdout


def test_identify_missing_file_fails() -> None:
    """A missing sample should produce a non-zero exit."""
    result = runner.invoke(app, ["identify", "/definitely/missing/sample.bin"])

    assert result.exit_code != 0
