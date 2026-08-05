"""Tests for Astra PE TLS callback analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.tls import TLSAnalyzer
from packages.schemas import AnalysisStatus


def _mock_section(
    *,
    name: bytes = b".text\x00\x00\x00",
    virtual_address: int = 0x1000,
    virtual_size: int = 0x1000,
    raw_size: int = 0x1000,
    characteristics: int = 0x60000020,
) -> MagicMock:
    """Create a representative PE section."""
    section = MagicMock()
    section.Name = name
    section.VirtualAddress = virtual_address
    section.Misc_VirtualSize = virtual_size
    section.SizeOfRawData = raw_size
    section.Characteristics = characteristics

    return section


def _mock_pe(
    *,
    tls_present: bool,
    callback_addresses: tuple[int, ...] = (),
    section: MagicMock | None = None,
    image_base: int = 0x140000000,
    size_of_image: int = 0x5000,
    address_of_callbacks: int = 0x140003000,
) -> MagicMock:
    """Create a representative mocked PE object."""
    pe = MagicMock()
    pe.OPTIONAL_HEADER.ImageBase = image_base
    pe.OPTIONAL_HEADER.SizeOfImage = size_of_image
    pe.OPTIONAL_HEADER.Magic = 0x20B

    pe.sections = [section or _mock_section()]

    if tls_present:
        tls_struct = MagicMock()
        tls_struct.StartAddressOfRawData = image_base + 0x2000
        tls_struct.EndAddressOfRawData = image_base + 0x2100
        tls_struct.AddressOfIndex = image_base + 0x2200
        tls_struct.AddressOfCallBacks = address_of_callbacks
        tls_struct.SizeOfZeroFill = 0
        tls_struct.Characteristics = 0

        pe.DIRECTORY_ENTRY_TLS.struct = tls_struct
    else:
        del pe.DIRECTORY_ENTRY_TLS

    image = bytearray(0x6000)
    table_rva = address_of_callbacks - image_base

    for index, callback_address in enumerate(callback_addresses):
        start = table_rva + index * 8
        image[start : start + 8] = callback_address.to_bytes(
            8,
            byteorder="little",
        )

    terminator = table_rva + len(callback_addresses) * 8
    image[terminator : terminator + 8] = b"\x00" * 8

    pe.get_memory_mapped_image.return_value = bytes(image)
    pe.get_offset_from_rva.side_effect = lambda rva: rva - 0xC00

    return pe


def test_tls_analyzer_contract() -> None:
    """The TLS analyzer should satisfy Astra's analyzer protocol."""
    analyzer = TLSAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_tls_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without a TLS directory should return no findings."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        tls_present=False,
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["tls_present"] is False
    assert result.data["callback_count"] == 0
    assert result.data["callbacks"] == []
    assert result.data["suspicious_callbacks"] == 0
    assert result.findings == ()


def test_valid_executable_tls_callback_is_normalized(
    tmp_path: Path,
) -> None:
    """A valid executable callback should be normalized."""
    sample = tmp_path / "tls.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000
    callback_address = image_base + 0x1000

    pe = _mock_pe(
        tls_present=True,
        callback_addresses=(callback_address,),
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["tls_present"] is True
    assert result.data["callback_count"] == 1
    assert result.data["mapped_callbacks"] == 1
    assert result.data["executable_callbacks"] == 1
    assert result.data["writable_callbacks"] == 0
    assert result.data["outside_image_callbacks"] == 0
    assert result.data["suspicious_callbacks"] == 0

    callback = result.data["callbacks"][0]

    assert callback["index"] == 0
    assert callback["section_name"] == ".text"
    assert callback["is_mapped"] is True
    assert callback["is_executable"] is True
    assert callback["is_writable"] is False
    assert callback["is_outside_image"] is False

    assert any(finding.title == "TLS callbacks present" for finding in result.findings)


def test_writable_tls_callback_is_suspicious(
    tmp_path: Path,
) -> None:
    """A callback in a writable section should be suspicious."""
    sample = tmp_path / "writable-tls.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000
    callback_address = image_base + 0x1000

    section = _mock_section(
        characteristics=0xE0000020,
    )

    pe = _mock_pe(
        tls_present=True,
        callback_addresses=(callback_address,),
        section=section,
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["writable_callbacks"] == 1
    assert result.data["suspicious_callbacks"] == 1

    assert any(
        finding.title == "Suspicious TLS callback locations detected" for finding in result.findings
    )


def test_callback_outside_image_is_suspicious(
    tmp_path: Path,
) -> None:
    """A callback outside the PE image should be suspicious."""
    sample = tmp_path / "outside.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000
    callback_address = image_base + 0x9000

    pe = _mock_pe(
        tls_present=True,
        callback_addresses=(callback_address,),
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["mapped_callbacks"] == 0
    assert result.data["outside_image_callbacks"] == 1
    assert result.data["suspicious_callbacks"] == 1

    callback = result.data["callbacks"][0]

    assert callback["is_outside_image"] is True
    assert callback["section_name"] is None

    assert any(
        finding.title == "Suspicious TLS callback locations detected" for finding in result.findings
    )


def test_non_executable_callback_is_suspicious(
    tmp_path: Path,
) -> None:
    """A callback in a non-executable section should be suspicious."""
    sample = tmp_path / "non-executable.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000
    callback_address = image_base + 0x1000

    section = _mock_section(
        characteristics=0x40000040,
    )

    pe = _mock_pe(
        tls_present=True,
        callback_addresses=(callback_address,),
        section=section,
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["executable_callbacks"] == 0
    assert result.data["suspicious_callbacks"] == 1

    assert any(
        finding.title == "Suspicious TLS callback locations detected" for finding in result.findings
    )


def test_many_tls_callbacks_generate_finding(
    tmp_path: Path,
) -> None:
    """An unusually large callback table should be reported."""
    sample = tmp_path / "many-callbacks.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000

    callback_addresses = tuple(image_base + 0x1000 + index * 8 for index in range(8))

    section = _mock_section(
        virtual_size=0x2000,
        raw_size=0x2000,
    )

    pe = _mock_pe(
        tls_present=True,
        callback_addresses=callback_addresses,
        section=section,
    )

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["callback_count"] == 8

    assert any(
        finding.title == "Unusually large TLS callback table detected"
        for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.tls.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = TLSAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = TLSAnalyzer()

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
    analyzer = TLSAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
