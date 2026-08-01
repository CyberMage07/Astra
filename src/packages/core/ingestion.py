"""Secure sample ingestion for Astra."""

import shutil
from pathlib import Path

from analyzers.hashing import calculate_hashes
from packages.config import AstraSettings
from packages.schemas import SampleMetadata


class SampleTooLargeError(ValueError):
    """Raised when a submitted sample exceeds the configured size limit."""


def ingest_sample(
    source_path: Path,
    settings: AstraSettings,
) -> SampleMetadata:
    """Validate, hash, and copy a sample into Astra quarantine storage."""
    source_path = source_path.expanduser().resolve()

    if not source_path.exists():
        raise FileNotFoundError(source_path)

    if not source_path.is_file():
        raise ValueError(f"Path is not a regular file: {source_path}")

    size_bytes = source_path.stat().st_size
    maximum_size = settings.max_sample_size_mb * 1024 * 1024

    if size_bytes > maximum_size:
        raise SampleTooLargeError(f"Sample size {size_bytes} exceeds limit of {maximum_size} bytes")

    hashes = calculate_hashes(source_path)
    quarantine_root = settings.resolved_storage_root / "quarantine"
    quarantine_root.mkdir(parents=True, exist_ok=True)

    destination = quarantine_root / hashes.sha256

    if not destination.exists():
        temporary_destination = destination.with_suffix(".part")
        shutil.copyfile(source_path, temporary_destination)
        temporary_destination.replace(destination)

    return SampleMetadata(
        original_name=source_path.name,
        source_path=destination,
        size_bytes=size_bytes,
        hashes=hashes,
    )
