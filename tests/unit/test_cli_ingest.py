"""Tests for Astra CLI sample ingestion."""

from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from apps.cli.main import app

runner = CliRunner()


def test_ingest_command(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """The CLI should ingest a sample and display its metadata."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"astra-cli-test")

    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["ingest", str(sample)])

    assert result.exit_code == 0
    assert "Sample Ingested" in result.stdout
    assert "sample.bin" in result.stdout
    assert "SHA-256" in result.stdout


def test_ingest_missing_file_fails() -> None:
    """A missing sample path should produce a non-zero exit."""
    result = runner.invoke(app, ["ingest", "/definitely/missing/file.bin"])

    assert result.exit_code != 0
