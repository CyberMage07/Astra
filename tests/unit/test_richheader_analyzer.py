"""Tests for Astra PE Rich Header analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.richheader import RichHeaderAnalyzer
from packages.schemas import AnalysisStatus

DANS_MARKER = 0x536E6144
DEFAULT_PE_OFFSET = 0x200
DEFAULT_DANS_OFFSET = 0x80


def _rotate_left_32(
    value: int,
    count: int,
) -> int:
    """Rotate an integer left within 32 bits."""
    value &= 0xFFFFFFFF
    rotation = count & 31

    if rotation == 0:
        return value

    return ((value << rotation) | (value >> (32 - rotation))) & 0xFFFFFFFF


def _rich_checksum(
    sample_data: bytes,
    *,
    rich_header_start: int,
    entries: tuple[tuple[int, int], ...],
) -> int:
    """Calculate a representative Rich Header checksum."""
    checksum = rich_header_start

    for index, byte in enumerate(sample_data[:rich_header_start]):
        if 0x3C <= index < 0x40:
            continue

        checksum = (
            checksum
            + _rotate_left_32(
                byte,
                index,
            )
        ) & 0xFFFFFFFF

    for component_id, count in entries:
        checksum = (
            checksum
            + _rotate_left_32(
                component_id,
                count,
            )
        ) & 0xFFFFFFFF

    return checksum


def _mock_pe() -> MagicMock:
    """Return a representative mocked PE object."""
    return MagicMock()


def _build_rich_sample(
    *,
    entries: tuple[tuple[int, int], ...],
    checksum_valid: bool = True,
    include_dans: bool = True,
    include_rich: bool = True,
) -> bytes:
    """Build synthetic PE data containing a Rich Header."""
    sample = bytearray(DEFAULT_PE_OFFSET + 64)

    sample[0:2] = b"MZ"
    sample[0x3C:0x40] = DEFAULT_PE_OFFSET.to_bytes(
        4,
        byteorder="little",
    )
    sample[DEFAULT_PE_OFFSET : DEFAULT_PE_OFFSET + 4] = b"PE\x00\x00"

    decoded_words: list[int] = []

    if include_dans:
        decoded_words.extend(
            (
                DANS_MARKER,
                0,
                0,
                0,
            )
        )
    else:
        decoded_words.extend(
            (
                0x11111111,
                0,
                0,
                0,
            )
        )

    for component_id, count in entries:
        decoded_words.extend(
            (
                component_id,
                count,
            )
        )

    rich_offset = DEFAULT_DANS_OFFSET + len(decoded_words) * 4

    temporary = bytes(sample)

    xor_key = _rich_checksum(
        temporary,
        rich_header_start=DEFAULT_DANS_OFFSET,
        entries=entries,
    )

    if not checksum_valid:
        xor_key ^= 0x01010101

    for index, value in enumerate(decoded_words):
        encoded = value ^ xor_key
        start = DEFAULT_DANS_OFFSET + index * 4

        sample[start : start + 4] = encoded.to_bytes(
            4,
            byteorder="little",
        )

    if include_rich:
        sample[rich_offset : rich_offset + 4] = b"Rich"
        sample[rich_offset + 4 : rich_offset + 8] = xor_key.to_bytes(
            4,
            byteorder="little",
        )

    return bytes(sample)


def test_richheader_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = RichHeaderAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_rich_header_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without a Rich marker should return an empty result."""
    sample = tmp_path / "without-rich.exe"

    sample_data = bytearray(DEFAULT_PE_OFFSET + 16)
    sample_data[0:2] = b"MZ"
    sample_data[0x3C:0x40] = DEFAULT_PE_OFFSET.to_bytes(
        4,
        byteorder="little",
    )
    sample_data[DEFAULT_PE_OFFSET : DEFAULT_PE_OFFSET + 4] = b"PE\x00\x00"

    sample.write_bytes(sample_data)

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["rich_header_present"] is False
    assert result.data["dans_offset"] is None
    assert result.data["rich_offset"] is None
    assert result.data["xor_key"] is None
    assert result.data["entry_count"] == 0
    assert result.data["entries"] == []
    assert result.findings == ()


def test_valid_rich_header_is_decoded(
    tmp_path: Path,
) -> None:
    """A valid Rich Header should be decoded and normalized."""
    sample = tmp_path / "valid-rich.exe"

    product_id = 0x00E1
    build_number = 30729
    component_id = (product_id << 16) | build_number

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    12,
                ),
            ),
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["rich_header_present"] is True
    assert result.data["malformed"] is False
    assert result.data["checksum_valid"] is True
    assert result.data["entry_count"] == 1
    assert result.data["total_object_count"] == 12
    assert result.data["unique_product_ids"] == [product_id]
    assert result.data["unique_build_numbers"] == [build_number]

    entry = result.data["entries"][0]

    assert entry["product_id"] == product_id
    assert entry["build_number"] == build_number
    assert entry["count"] == 12
    assert entry["component_id"] == component_id
    assert entry["toolchain_family"] == ("Visual Studio 2019")
    assert result.findings == ()


def test_malformed_rich_header_generates_finding(
    tmp_path: Path,
) -> None:
    """A Rich marker without a valid DanS header should be malformed."""
    sample = tmp_path / "malformed-rich.exe"

    component_id = (0x00E1 << 16) | 30729

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    1,
                ),
            ),
            include_dans=False,
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["rich_header_present"] is True
    assert result.data["malformed"] is True
    assert result.data["entry_count"] == 0

    assert any(finding.title == "Malformed PE Rich Header detected" for finding in result.findings)


def test_checksum_mismatch_generates_finding(
    tmp_path: Path,
) -> None:
    """An invalid Rich checksum should generate a finding."""
    sample = tmp_path / "checksum-mismatch.exe"

    component_id = (0x00E1 << 16) | 30729

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    3,
                ),
            ),
            checksum_valid=False,
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["checksum_valid"] is False

    assert any(finding.title == "Rich Header checksum mismatch" for finding in result.findings)


def test_unknown_product_identifier_generates_info_finding(
    tmp_path: Path,
) -> None:
    """Unknown product identifiers should remain visible."""
    sample = tmp_path / "unknown-product.exe"

    product_id = 0xF123
    component_id = (product_id << 16) | 1234

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    4,
                ),
            ),
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["unknown_product_entries"] == 1
    assert result.data["entries"][0]["product_name"] is None
    assert result.data["entries"][0]["toolchain_family"] is None

    assert any(
        finding.title == "Unknown Rich Header product identifiers detected"
        for finding in result.findings
    )


def test_duplicate_component_entries_are_counted(
    tmp_path: Path,
) -> None:
    """Duplicate Rich component records should be counted."""
    sample = tmp_path / "duplicate-rich.exe"

    component_id = (0x00E1 << 16) | 30729

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    2,
                ),
                (
                    component_id,
                    3,
                ),
            ),
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["entry_count"] == 2
    assert result.data["duplicate_entries"] == 1
    assert result.data["total_object_count"] == 5


def test_zero_count_entry_generates_info_finding(
    tmp_path: Path,
) -> None:
    """Zero-count component records should be reported."""
    sample = tmp_path / "zero-count.exe"

    component_id = (0x00E1 << 16) | 30729

    sample.write_bytes(
        _build_rich_sample(
            entries=(
                (
                    component_id,
                    0,
                ),
            ),
        )
    )

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        return_value=_mock_pe(),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["zero_count_entries"] == 1

    assert any(
        finding.title == "Zero-count Rich Header entries detected" for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)

    with patch(
        "analyzers.richheader.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = RichHeaderAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = RichHeaderAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.exe")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as samples."""
    analyzer = RichHeaderAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
