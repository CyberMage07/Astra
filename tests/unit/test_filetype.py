"""Tests for Astra content-based file identification."""

from pathlib import Path

import pytest

from analyzers.filetype import identify_file


def test_text_file_is_identified(tmp_path: Path) -> None:
    """A plain text file should be identified correctly."""
    sample = tmp_path / "notes.txt"
    sample.write_text("Hello from Astra!\n", encoding="utf-8")

    result = identify_file(sample)

    assert result.file_name == "notes.txt"
    assert result.extension == ".txt"
    assert result.detected_family == "text"
    assert result.is_executable is False
    assert result.confidence >= 85


def test_extension_mismatch_is_detected(tmp_path: Path) -> None:
    """Renaming a text file should produce an extension mismatch."""
    sample = tmp_path / "fake.pdf"
    sample.write_text("This is definitely not a PDF.", encoding="utf-8")

    result = identify_file(sample)

    assert result.detected_family == "text"
    assert result.extension == ".pdf"
    assert result.extension_matches is False


def test_missing_file_raises() -> None:
    """Missing files should raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        identify_file(Path("/definitely/missing/file.bin"))


def test_directory_is_rejected(tmp_path: Path) -> None:
    """Directories are not valid samples."""
    with pytest.raises(ValueError, match="regular file"):
        identify_file(tmp_path)
