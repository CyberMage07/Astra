"""Cryptographic hashing for submitted samples."""

import hashlib
from pathlib import Path

from packages.schemas import FileHashes

DEFAULT_CHUNK_SIZE = 1024 * 1024


def calculate_hashes(
    file_path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> FileHashes:
    """Calculate hashes without loading the entire file into memory."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    if not file_path.exists():
        raise FileNotFoundError(file_path)

    if not file_path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }

    with file_path.open("rb") as sample:
        while chunk := sample.read(chunk_size):
            for hasher in hashers.values():
                hasher.update(chunk)

    return FileHashes(
        md5=hashers["md5"].hexdigest(),
        sha1=hashers["sha1"].hexdigest(),
        sha256=hashers["sha256"].hexdigest(),
        sha512=hashers["sha512"].hexdigest(),
    )
