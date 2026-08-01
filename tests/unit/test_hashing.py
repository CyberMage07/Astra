"""Tests for Astra sample hashing."""

import hashlib
from pathlib import Path

import pytest

from analyzers.hashing import calculate_hashes


def test_calculate_hashes(tmp_path: Path) -> None:
    """Astra should calculate deterministic hashes for a sample."""
    sample = tmp_path / "sample.bin"
    content = b"astra-test-sample\n"
    sample.write_bytes(content)

    result = calculate_hashes(sample)

    assert result.md5 == hashlib.md5(content, usedforsecurity=False).hexdigest()
    assert result.sha1 == hashlib.sha1(content, usedforsecurity=False).hexdigest()
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.sha512 == hashlib.sha512(content).hexdigest()


def test_missing_file_raises_error(tmp_path: Path) -> None:
    """A missing sample should raise FileNotFoundError."""
    missing = tmp_path / "missing.bin"

    with pytest.raises(FileNotFoundError):
        calculate_hashes(missing)


def test_directory_is_rejected(tmp_path: Path) -> None:
    """Directories must not be accepted as samples."""
    with pytest.raises(ValueError, match="regular file"):
        calculate_hashes(tmp_path)


def test_invalid_chunk_size_is_rejected(tmp_path: Path) -> None:
    """Chunk sizes must be greater than zero."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    with pytest.raises(ValueError, match="chunk_size"):
        calculate_hashes(sample, chunk_size=0)
