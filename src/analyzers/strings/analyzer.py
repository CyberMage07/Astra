"""String extraction for Astra samples."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path

from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
    AnalyzerError,
    ExtractedString,
    StringEncoding,
    StringsAnalysisData,
)

ASCII_PATTERN_TEMPLATE = rb"[\x20-\x7e]{%d,}"


def _extract_ascii(data: bytes, minimum_length: int) -> list[ExtractedString]:
    """Extract printable ASCII strings."""
    pattern = re.compile(ASCII_PATTERN_TEMPLATE % minimum_length)

    return [
        ExtractedString(
            value=match.group().decode("ascii", errors="replace"),
            offset=match.start(),
            encoding=StringEncoding.ASCII,
            length=len(match.group()),
        )
        for match in pattern.finditer(data)
    ]


def _scan_utf16(
    data: bytes,
    minimum_length: int,
    encoding: StringEncoding,
) -> list[ExtractedString]:
    """Extract aligned printable UTF-16 strings."""
    extracted: list[ExtractedString] = []
    data_length = len(data)

    for start in range(data_length - 1):
        if encoding is StringEncoding.UTF16_LE:
            printable_index = start
            null_index = start + 1
        else:
            null_index = start
            printable_index = start + 1

        if data[null_index] != 0 or not 0x20 <= data[printable_index] <= 0x7E:
            continue

        # Avoid starting midway through an existing ASCII or UTF-16 sequence.
        if start > 0 and 0x20 <= data[start - 1] <= 0x7E:
            continue

        cursor = start
        character_count = 0

        while cursor + 1 < data_length:
            first = data[cursor]
            second = data[cursor + 1]

            if encoding is StringEncoding.UTF16_LE:
                valid_pair = 0x20 <= first <= 0x7E and second == 0
            else:
                valid_pair = first == 0 and 0x20 <= second <= 0x7E

            if not valid_pair:
                break

            character_count += 1
            cursor += 2

        if character_count < minimum_length:
            continue

        raw_value = data[start:cursor]
        extracted.append(
            ExtractedString(
                value=raw_value.decode(encoding.value, errors="replace"),
                offset=start,
                encoding=encoding,
                length=character_count,
            )
        )

    return extracted


def _ranges_overlap(first: ExtractedString, second: ExtractedString) -> bool:
    """Return whether two extracted strings occupy overlapping bytes."""
    first_width = first.length if first.encoding is StringEncoding.ASCII else first.length * 2
    second_width = second.length if second.encoding is StringEncoding.ASCII else second.length * 2

    first_end = first.offset + first_width
    second_end = second.offset + second_width

    return first.offset < second_end and second.offset < first_end


def _remove_utf16_overlaps(
    strings: list[ExtractedString],
) -> list[ExtractedString]:
    """Remove shifted or competing UTF-16 interpretations."""
    accepted: list[ExtractedString] = []

    ranked = sorted(
        strings,
        key=lambda item: (
            -item.length,
            item.offset,
            item.encoding.value,
        ),
    )

    for candidate in ranked:
        competing = any(
            candidate.encoding is not StringEncoding.ASCII
            and existing.encoding is not StringEncoding.ASCII
            and _ranges_overlap(candidate, existing)
            for existing in accepted
        )

        if not competing:
            accepted.append(candidate)

    return sorted(
        accepted,
        key=lambda item: (item.offset, item.encoding.value),
    )


class StringsAnalyzer:
    """Extract readable strings from supported sample types."""

    name = "strings"
    version = "0.1.0"
    supported_families = frozenset(
        {
            "pe",
            "elf",
            "mach-o",
            "pdf",
            "office",
            "apk",
            "archive",
            "script",
            "text",
            "unknown",
        }
    )

    def __init__(
        self,
        *,
        minimum_length: int = 4,
        maximum_results: int = 10_000,
    ) -> None:
        """Initialize configurable extraction limits."""
        if minimum_length < 1:
            raise ValueError("minimum_length must be greater than zero")

        if maximum_results < 1:
            raise ValueError("maximum_results must be greater than zero")

        self.minimum_length = minimum_length
        self.maximum_results = maximum_results

    def supports(self, family: str) -> bool:
        """Return whether this analyzer supports the file family."""
        return family in self.supported_families

    def analyze(self, sample_path: Path) -> AnalysisResult:
        """Extract strings and return normalized results."""
        started_at = datetime.now(UTC)
        start = time.perf_counter()

        try:
            resolved_path = sample_path.expanduser().resolve()

            if not resolved_path.exists():
                raise FileNotFoundError(resolved_path)

            if not resolved_path.is_file():
                raise ValueError(f"Path is not a regular file: {resolved_path}")

            data = resolved_path.read_bytes()

            extracted = _remove_utf16_overlaps(
                _extract_ascii(data, self.minimum_length)
                + _scan_utf16(data, self.minimum_length, StringEncoding.UTF16_LE)
                + _scan_utf16(data, self.minimum_length, StringEncoding.UTF16_BE)
            )

            truncated = len(extracted) > self.maximum_results
            visible = tuple(extracted[: self.maximum_results])

            analysis_data = StringsAnalysisData(
                strings=visible,
                total_count=len(extracted),
                truncated=truncated,
                minimum_length=self.minimum_length,
            )

            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.COMPLETED,
                started_at=started_at,
                duration_ms=duration_ms,
                data=analysis_data.model_dump(mode="json"),
            )

        except (FileNotFoundError, ValueError):
            raise
        except Exception as error:
            duration_ms = int((time.perf_counter() - start) * 1000)

            return AnalysisResult(
                analyzer=self.name,
                analyzer_version=self.version,
                status=AnalysisStatus.PARTIAL,
                started_at=started_at,
                duration_ms=duration_ms,
                errors=(
                    AnalyzerError(
                        error_type=type(error).__name__,
                        message=str(error),
                        recoverable=True,
                    ),
                ),
            )
