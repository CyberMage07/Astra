"""Tests for Astra ELF packer and obfuscation analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfpacker import ELFPackerAnalyzer
from packages.schemas import AnalysisStatus


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.header = {
        "e_entry": 0x401000,
    }

    elf.iter_sections.return_value = []
    elf.get_section_by_name.return_value = None

    return elf


def _mock_section(
    *,
    name: str = ".text",
    section_type: str = "SHT_PROGBITS",
    address: int = 0x401000,
    offset: int = 0x100,
    size: int = 0x100,
    flags: int = 0x6,
    data: bytes | None = None,
) -> MagicMock:
    """Create one mocked ELF section."""
    section = MagicMock()

    section.name = name

    section.header = {
        "sh_type": section_type,
        "sh_addr": address,
        "sh_offset": offset,
        "sh_size": size,
        "sh_flags": flags,
    }

    if data is None:
        section.data.return_value = b"A" * size
    else:
        section.data.return_value = data

    return section


def test_elfpacker_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFPackerAnalyzer()

    assert isinstance(
        analyzer,
        Analyzer,
    )

    assert analyzer.supports("elf") is True

    assert analyzer.supports("pe") is False


def test_benign_elf_scores_zero(
    tmp_path: Path,
) -> None:
    """A normal ELF should not look packed."""
    sample = tmp_path / "benign.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=50,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=100,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["packed_score"] == 0

    assert result.data["packed_likelihood"] == "unlikely-packed"

    assert result.findings == ()


def test_known_packer_signature_scores_40(
    tmp_path: Path,
) -> None:
    """Known packer section naming should strongly contribute."""
    sample = tmp_path / "upx.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                1,
                "UPX",
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=30,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=100,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["known_packer_signature"] is True

    assert result.data["suspected_packer"] == "UPX"

    assert result.data["packed_score"] >= 40

    assert result.findings


def test_high_entropy_executable_section_adds_score(
    tmp_path: Path,
) -> None:
    """High-entropy executable content should add weight."""
    sample = tmp_path / "entropy.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                1,
                1,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=50,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["executable_high_entropy_count"] == 1

    assert result.data["packed_score"] == 20

    assert result.data["packed_likelihood"] == "weak-indications"


def test_rwx_section_adds_score(
    tmp_path: Path,
) -> None:
    """RWX sections should contribute to packing suspicion."""
    sample = tmp_path / "rwx.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                1,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=50,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["rwx_section_count"] == 1

    assert result.data["packed_score"] == 15


def test_suspicious_section_name_adds_score(
    tmp_path: Path,
) -> None:
    """Packing-like section names should contribute."""
    sample = tmp_path / "named.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                1,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=50,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["suspicious_section_name_count"] == 1

    assert result.data["packed_score"] == 15


def test_stripped_sparse_symbols_add_score(
    tmp_path: Path,
) -> None:
    """Stripped binaries with very few imports should add suspicion."""
    sample = tmp_path / "sparse.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=3,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["stripped"] is True

    assert result.data["packed_score"] == 10


def test_unusual_entry_point_adds_score(
    tmp_path: Path,
) -> None:
    """Entry points outside executable sections should contribute."""
    sample = tmp_path / "entry.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=10,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["unusual_entry_point"] is True

    assert result.data["packed_score"] == 10


def test_unusual_relocation_profile_adds_score(
    tmp_path: Path,
) -> None:
    """Imports without relocations should contribute."""
    sample = tmp_path / "relocations.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=12,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=0,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["relocation_count"] == 0

    assert result.data["packed_score"] == 10


def test_dynamic_loading_adds_five_points(
    tmp_path: Path,
) -> None:
    """dlopen+dlsym should remain a weak supporting signal."""
    sample = tmp_path / "dynamic.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=30,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=100,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["suspicious_dynamic_loading"] is True

    assert result.data["packed_score"] == 5

    assert result.findings == ()


def test_suspicious_layout_adds_score(
    tmp_path: Path,
) -> None:
    """Overlapping section layout should add suspicion."""
    sample = tmp_path / "layout.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                0,
                0,
                0,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=20,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=50,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=True,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["suspicious_layout"] is True

    assert result.data["packed_score"] == 10


def test_score_is_capped_at_100(
    tmp_path: Path,
) -> None:
    """Combined indicators should never exceed 100."""
    sample = tmp_path / "packed.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                5,
                3,
                2,
                2,
                "UPX",
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=2,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=0,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=True,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["packed_score"] == 100

    assert result.data["packed_likelihood"] == "strongly-packed"

    assert result.findings


def test_likelihood_thresholds() -> None:
    """Packer score ranges should remain stable."""
    from analyzers.elfpacker.analyzer import _likelihood

    assert _likelihood(0) == "unlikely-packed"

    assert _likelihood(19) == "unlikely-packed"

    assert _likelihood(20) == "weak-indications"

    assert _likelihood(39) == "weak-indications"

    assert _likelihood(40) == "suspicious"

    assert _likelihood(59) == "suspicious"

    assert _likelihood(60) == "likely-packed"

    assert _likelihood(79) == "likely-packed"

    assert _likelihood(80) == "strongly-packed"

    assert _likelihood(100) == "strongly-packed"


def test_finding_requires_score_40(
    tmp_path: Path,
) -> None:
    """Weak packer evidence should not create a security finding."""
    sample = tmp_path / "weak.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfpacker.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfpacker.analyzer._collect_section_signals",
            return_value=(
                1,
                1,
                1,
                0,
                None,
            ),
        ),
        patch(
            "analyzers.elfpacker.analyzer._is_stripped",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._symbol_table_present",
            return_value=True,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_imports",
            return_value=30,
        ),
        patch(
            "analyzers.elfpacker.analyzer._count_relocations",
            return_value=100,
        ),
        patch(
            "analyzers.elfpacker.analyzer._entry_point_unusual",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_dynamic_loading",
            return_value=False,
        ),
        patch(
            "analyzers.elfpacker.analyzer._suspicious_layout",
            return_value=False,
        ),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.data["packed_score"] == 35

    assert result.findings == ()


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfpacker.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

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
        "analyzers.elfpacker.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFPackerAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED

    assert result.errors

    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ELFPackerAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.elf")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted as samples."""
    analyzer = ELFPackerAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
