"""Tests for Astra ELF dynamic-linking analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfdynamic import ELFDynamicLinkingAnalyzer
from packages.schemas import AnalysisStatus


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.elfclass = 64
    elf.iter_sections.return_value = []
    elf.iter_segments.return_value = []

    return elf


def _mock_section(
    *,
    name: str = ".plt",
    section_type: str = "SHT_PROGBITS",
    address: int = 0x401000,
    offset: int = 0x1000,
    size: int = 0x100,
    entry_size: int = 16,
    flags: int = 0x6,
) -> MagicMock:
    """Create one mocked ELF section."""
    section = MagicMock()

    section.name = name

    section.header = {
        "sh_type": section_type,
        "sh_addr": address,
        "sh_offset": offset,
        "sh_size": size,
        "sh_entsize": entry_size,
        "sh_flags": flags,
    }

    return section


def _mock_segment(
    *,
    segment_type: str,
) -> MagicMock:
    """Create one mocked ELF segment."""
    segment = MagicMock()

    segment.header = {
        "p_type": segment_type,
    }

    return segment


def test_elfdynamic_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFDynamicLinkingAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )

    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_dynamic_linking_present_when_sections_exist(
    tmp_path: Path,
) -> None:
    """PLT/GOT sections should indicate dynamic linking."""
    sample = tmp_path / "dynamic.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    plt = _mock_section(
        name=".plt",
    )

    got = _mock_section(
        name=".got",
        flags=0x3,
    )

    elf.iter_sections.return_value = [
        plt,
        got,
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dynamic_linking_present"] is True
    assert result.data["plt_present"] is True
    assert result.data["got_present"] is True


def test_plt_section_is_normalized(
    tmp_path: Path,
) -> None:
    """PLT section metadata should be normalized."""
    sample = tmp_path / "plt.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    plt = _mock_section(
        name=".plt",
        size=256,
        entry_size=16,
        flags=0x6,
    )

    elf.iter_sections.return_value = [
        plt,
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["plt_present"] is True
    assert result.data["plt_section_count"] == 1

    section = result.data["sections"][0]

    assert section["name"] == ".plt"
    assert section["entry_count"] == 16
    assert section["executable"] is True
    assert section["allocatable"] is True


def test_got_and_got_plt_are_detected(
    tmp_path: Path,
) -> None:
    """GOT-related sections should be counted."""
    sample = tmp_path / "got.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    got = _mock_section(
        name=".got",
        size=64,
        entry_size=8,
        flags=0x3,
    )

    got_plt = _mock_section(
        name=".got.plt",
        size=32,
        entry_size=8,
        flags=0x3,
    )

    elf.iter_sections.return_value = [
        got,
        got_plt,
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["got_present"] is True
    assert result.data["got_plt_present"] is True
    assert result.data["got_section_count"] == 2
    assert result.data["got_entry_estimate"] == 12


def test_plt_got_and_plt_sec_are_detected(
    tmp_path: Path,
) -> None:
    """Modern alternate PLT sections should be recognized."""
    sample = tmp_path / "plt-modern.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_sections.return_value = [
        _mock_section(
            name=".plt.got",
        ),
        _mock_section(
            name=".plt.sec",
        ),
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["plt_got_present"] is True
    assert result.data["plt_sec_present"] is True
    assert result.data["plt_section_count"] == 2


def test_relro_is_detected(
    tmp_path: Path,
) -> None:
    """PT_GNU_RELRO should enable RELRO detection."""
    sample = tmp_path / "relro.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_segments.return_value = [
        _mock_segment(
            segment_type="PT_GNU_RELRO",
        )
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["relro"] is True


def test_bind_now_enables_full_relro(
    tmp_path: Path,
) -> None:
    """RELRO + BIND_NOW should produce full RELRO."""
    sample = tmp_path / "full-relro.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_BIND_NOW": MagicMock(),
                },
                0,
            ),
        ),
        patch(
            "analyzers.elfdynamic.analyzer._has_relro",
            return_value=True,
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["bind_now"] is True
    assert result.data["relro"] is True
    assert result.data["full_relro"] is True
    assert result.data["lazy_binding"] is False


def test_dt_flags_bind_now_is_detected(
    tmp_path: Path,
) -> None:
    """DF_BIND_NOW in DT_FLAGS should enable eager binding."""
    sample = tmp_path / "flags.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    tag = MagicMock()
    tag.entry.d_val = 0x8
    tag.entry.d_ptr = None

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_FLAGS": tag,
                },
                0,
            ),
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["bind_now"] is True


def test_dt_flags_1_now_is_detected(
    tmp_path: Path,
) -> None:
    """DF_1_NOW in DT_FLAGS_1 should enable eager binding."""
    sample = tmp_path / "flags1.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    tag = MagicMock()
    tag.entry.d_val = 0x1
    tag.entry.d_ptr = None

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_FLAGS_1": tag,
                },
                0,
            ),
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["bind_now"] is True


def test_dynamic_tag_addresses_are_extracted(
    tmp_path: Path,
) -> None:
    """PLTGOT and JMPREL dynamic pointers should be normalized."""
    sample = tmp_path / "tags.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    pltgot = MagicMock()
    pltgot.entry.d_ptr = 0x404000
    pltgot.entry.d_val = None

    jmprel = MagicMock()
    jmprel.entry.d_ptr = 0x400600
    jmprel.entry.d_val = None

    pltrelsz = MagicMock()
    pltrelsz.entry.d_ptr = None
    pltrelsz.entry.d_val = 360

    pltrel = MagicMock()
    pltrel.entry.d_ptr = None
    pltrel.entry.d_val = 7

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_PLTGOT": pltgot,
                    "DT_JMPREL": jmprel,
                    "DT_PLTRELSZ": pltrelsz,
                    "DT_PLTREL": pltrel,
                },
                0,
            ),
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["plt_got_address"] == 0x404000
    assert result.data["jmprel_address"] == 0x400600
    assert result.data["plt_relocation_size"] == 360
    assert result.data["plt_relocation_type"] == "DT_RELA"


def test_dt_rel_type_is_normalized(
    tmp_path: Path,
) -> None:
    """DT_REL should be surfaced correctly."""
    sample = tmp_path / "rel.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    tag = MagicMock()
    tag.entry.d_ptr = None
    tag.entry.d_val = 17

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_PLTREL": tag,
                },
                0,
            ),
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["plt_relocation_type"] == "DT_REL"


def test_plt_relocation_count_is_preserved(
    tmp_path: Path,
) -> None:
    """PLT relocation count should be included."""
    sample = tmp_path / "relocations.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._plt_relocation_count",
            return_value=15,
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["plt_relocation_count"] == 15
    assert result.data["plt_entry_count"] == 15


def test_lazy_binding_is_detected(
    tmp_path: Path,
) -> None:
    """PLT relocations without BIND_NOW should indicate lazy binding."""
    sample = tmp_path / "lazy.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_sections.return_value = [
        _mock_section(
            name=".got",
            flags=0x3,
        )
    ]

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._plt_relocation_count",
            return_value=10,
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["dynamic_linking_present"] is True
    assert result.data["bind_now"] is False
    assert result.data["lazy_binding"] is True


def test_lazy_binding_with_writable_got_generates_finding(
    tmp_path: Path,
) -> None:
    """Writable GOT + lazy binding should generate a contextual finding."""
    sample = tmp_path / "weak-binding.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_sections.return_value = [
        _mock_section(
            name=".got",
            flags=0x3,
        )
    ]

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._plt_relocation_count",
            return_value=10,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._has_relro",
            return_value=False,
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["lazy_binding"] is True
    assert result.data["writable_got"] is True
    assert result.data["full_relro"] is False
    assert result.data["suspicious_dynamic_linking"] is True

    assert any(
        finding.title == "Writable GOT with lazy binding detected" for finding in result.findings
    )


def test_full_relro_suppresses_writable_got_finding(
    tmp_path: Path,
) -> None:
    """Full RELRO should suppress the lazy-binding GOT finding."""
    sample = tmp_path / "protected.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_sections.return_value = [
        _mock_section(
            name=".got",
            flags=0x3,
        )
    ]

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {
                    "DT_BIND_NOW": MagicMock(),
                },
                0,
            ),
        ),
        patch(
            "analyzers.elfdynamic.analyzer._has_relro",
            return_value=True,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._plt_relocation_count",
            return_value=10,
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["full_relro"] is True
    assert result.data["lazy_binding"] is False
    assert result.data["suspicious_dynamic_linking"] is False
    assert result.findings == ()


def test_writable_got_is_detected(
    tmp_path: Path,
) -> None:
    """Writable GOT sections should be surfaced."""
    sample = tmp_path / "writable.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    elf.iter_sections.return_value = [
        _mock_section(
            name=".got",
            flags=0x3,
        )
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["writable_got"] is True


def test_malformed_dynamic_metadata_generates_finding(
    tmp_path: Path,
) -> None:
    """Malformed PLT/GOT metadata should generate a finding."""
    sample = tmp_path / "malformed.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfdynamic.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfdynamic.analyzer._collect_linking_sections",
            return_value=(
                (),
                2,
            ),
        ),
        patch(
            "analyzers.elfdynamic.analyzer._dynamic_tags",
            return_value=(
                {},
                1,
            ),
        ),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 3

    assert any(
        finding.title == "Malformed ELF dynamic-linking metadata detected"
        for finding in result.findings
    )


def test_32_bit_got_entry_estimate(
    tmp_path: Path,
) -> None:
    """32-bit ELF GOT entry size should use 4-byte pointers."""
    sample = tmp_path / "32bit.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()
    elf.elfclass = 32

    elf.iter_sections.return_value = [
        _mock_section(
            name=".got",
            size=40,
            flags=0x3,
        )
    ]

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.data["got_entry_estimate"] == 10


def test_no_dynamic_metadata_returns_empty_result(
    tmp_path: Path,
) -> None:
    """Static or minimal ELF binaries should remain clean."""
    sample = tmp_path / "static.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dynamic_linking_present"] is False
    assert result.data["plt_entry_count"] == 0
    assert result.data["got_entry_estimate"] == 0
    assert result.findings == ()


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_invalid_elf_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid ELF parsing should return a failed result."""
    sample = tmp_path / "invalid.elf"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.elfdynamic.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFDynamicLinkingAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing files should raise FileNotFoundError."""
    analyzer = ELFDynamicLinkingAnalyzer()

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
    analyzer = ELFDynamicLinkingAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
