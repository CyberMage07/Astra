"""Tests for Astra sample ingestion."""

from pathlib import Path

import pytest

from packages.config import AstraSettings
from packages.core import SampleTooLargeError, ingest_sample


def test_sample_is_ingested_into_quarantine(tmp_path: Path) -> None:
    """A submitted sample should be stored using its SHA-256 hash."""
    source = tmp_path / "suspicious.bin"
    source.write_bytes(b"harmless-test-content")
    settings = AstraSettings(project_root=tmp_path)

    metadata = ingest_sample(source, settings)

    expected_path = tmp_path / "storage" / "quarantine" / metadata.hashes.sha256
    assert metadata.original_name == "suspicious.bin"
    assert metadata.size_bytes == len(b"harmless-test-content")
    assert metadata.source_path == expected_path
    assert expected_path.read_bytes() == b"harmless-test-content"


def test_duplicate_sample_is_deduplicated(tmp_path: Path) -> None:
    """Identical samples should resolve to the same quarantine file."""
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"same-content")
    second.write_bytes(b"same-content")
    settings = AstraSettings(project_root=tmp_path)

    first_metadata = ingest_sample(first, settings)
    second_metadata = ingest_sample(second, settings)

    assert first_metadata.source_path == second_metadata.source_path
    assert first_metadata.hashes.sha256 == second_metadata.hashes.sha256


def test_oversized_sample_is_rejected(tmp_path: Path) -> None:
    """Samples exceeding the configured limit must be rejected."""
    source = tmp_path / "large.bin"
    source.write_bytes(b"x" * (1024 * 1024 + 1))
    settings = AstraSettings(project_root=tmp_path, max_sample_size_mb=1)

    with pytest.raises(SampleTooLargeError):
        ingest_sample(source, settings)
