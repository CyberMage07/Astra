"""Tests for Astra ELF static analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elf import ELFAnalyzer
from packages.schemas import (
    AnalysisStatus,
    ELFDynamicInfo,
)


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.elfclass = 64
    elf.little_endian = True

    elf.header = {
        "e_type": "ET_DYN",
        "e_machine": "EM_X86_64",
        "e_ident": {
            "EI_OSABI": "ELFOSABI_SYSV",
            "EI_ABIVERSION": 0,
        },
        "e_version": 1,
        "e_entry": 0x401000,
        "e_phoff": 64,
        "e_shoff": 4096,
        "e_phnum": 4,
        "e_shnum": 5,
        "e_flags": 0,
    }

    elf.iter_sections.return_value = []
    elf.iter_segments.return_value = []
    elf.get_section_by_name.return_value = None

    return elf


def test_elf_analyzer_contract() -> None:
    """The ELF analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ELFAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_minimal_elf_is_normalized(
    tmp_path: Path,
) -> None:
    """Basic ELF header information should be normalized."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["elf_present"] is True

    header = result.data["header"]

    assert header["architecture_bits"] == 64
    assert header["endianness"] == "little"
    assert header["elf_type"] == "ET_DYN"
    assert header["machine"] == "x86-64"
    assert header["os_abi"] == "System V"
    assert header["entry_point"] == 0x401000


def test_big_endian_elf_is_normalized(
    tmp_path: Path,
) -> None:
    """Big-endian ELF files should be represented correctly."""
    sample = tmp_path / "big.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()
    elf.little_endian = False

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["header"]["endianness"] == "big"


def test_sections_are_normalized(
    tmp_path: Path,
) -> None:
    """ELF sections should preserve permissions and layout."""
    sample = tmp_path / "sections.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    section = MagicMock()
    section.name = ".text"
    section.header = {
        "sh_type": "SHT_PROGBITS",
        "sh_addr": 0x401000,
        "sh_offset": 0x1000,
        "sh_size": 0x200,
        "sh_entsize": 0,
        "sh_flags": 0x6,
        "sh_addralign": 16,
    }

    elf.iter_sections.return_value = [section]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["section_count"] == 1

    normalized = result.data["sections"][0]

    assert normalized["name"] == ".text"
    assert normalized["address"] == 0x401000
    assert normalized["executable"] is True
    assert normalized["allocatable"] is True
    assert normalized["writable"] is False


def test_segments_are_normalized(
    tmp_path: Path,
) -> None:
    """ELF program headers should preserve memory permissions."""
    sample = tmp_path / "segments.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    segment = MagicMock()
    segment.header = {
        "p_type": "PT_LOAD",
        "p_offset": 0,
        "p_vaddr": 0x400000,
        "p_paddr": 0x400000,
        "p_filesz": 4096,
        "p_memsz": 4096,
        "p_flags": 0x5,
        "p_align": 4096,
    }

    elf.iter_segments.return_value = [segment]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["segment_count"] == 1

    normalized = result.data["segments"][0]

    assert normalized["segment_type"] == "PT_LOAD"
    assert normalized["readable"] is True
    assert normalized["executable"] is True
    assert normalized["writable"] is False


def test_executable_stack_generates_finding(
    tmp_path: Path,
) -> None:
    """An executable PT_GNU_STACK should produce a finding."""
    sample = tmp_path / "exec-stack.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    segment = MagicMock()
    segment.header = {
        "p_type": "PT_GNU_STACK",
        "p_offset": 0,
        "p_vaddr": 0,
        "p_paddr": 0,
        "p_filesz": 0,
        "p_memsz": 0,
        "p_flags": 0x7,
        "p_align": 16,
    }

    elf.iter_segments.return_value = [segment]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    security = result.data["security"]

    assert security["executable_stack"] is True
    assert security["nx_enabled"] is False

    assert any(finding.title == "Executable ELF stack detected" for finding in result.findings)


def test_nx_stack_is_detected(
    tmp_path: Path,
) -> None:
    """A non-executable PT_GNU_STACK should imply NX."""
    sample = tmp_path / "nx.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    segment = MagicMock()
    segment.header = {
        "p_type": "PT_GNU_STACK",
        "p_offset": 0,
        "p_vaddr": 0,
        "p_paddr": 0,
        "p_filesz": 0,
        "p_memsz": 0,
        "p_flags": 0x6,
        "p_align": 16,
    }

    elf.iter_segments.return_value = [segment]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    security = result.data["security"]

    assert security["nx_enabled"] is True
    assert security["executable_stack"] is False


def test_relro_is_detected(
    tmp_path: Path,
) -> None:
    """PT_GNU_RELRO should enable RELRO detection."""
    sample = tmp_path / "relro.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    segment = MagicMock()
    segment.header = {
        "p_type": "PT_GNU_RELRO",
        "p_offset": 0,
        "p_vaddr": 0x500000,
        "p_paddr": 0x500000,
        "p_filesz": 1024,
        "p_memsz": 1024,
        "p_flags": 0x4,
        "p_align": 4096,
    }

    elf.iter_segments.return_value = [segment]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.data["security"]["relro"] is True


def test_rpath_generates_finding(
    tmp_path: Path,
) -> None:
    """DT_RPATH should be surfaced as a contextual finding."""
    sample = tmp_path / "rpath.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    dynamic_info = ELFDynamicInfo(
        dynamically_linked=True,
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed_libraries=(),
        soname=None,
        rpath="/tmp/lib",
        runpath=None,
        bind_now=False,
        dynamic_entry_count=1,
    )

    with (
        patch(
            "analyzers.elf.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elf.analyzer._extract_dynamic",
            return_value=dynamic_info,
        ),
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["dynamic"]["rpath"] == "/tmp/lib"
    assert result.data["security"]["has_rpath"] is True

    assert any(finding.title == "ELF RPATH configured" for finding in result.findings)


def test_malformed_section_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed sections should not abort the full analysis."""
    sample = tmp_path / "malformed-section.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    section = MagicMock()
    section.name = ".bad"

    section.header.get.side_effect = RuntimeError("broken section")

    elf.iter_sections.return_value = [section]

    with patch(
        "analyzers.elf.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed"] is True
    assert result.data["malformed_section_count"] == 1


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elf.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Clearly invalid ELF structures should fail cleanly."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"not-an-elf")

    with patch(
        "analyzers.elf.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ELFAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.elf")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as ELF samples."""
    analyzer = ELFAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
