"""Tests for Astra ELF compiler, toolchain, and build provenance analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elftoolchain import ELFToolchainAnalyzer
from packages.schemas import (
    AnalysisStatus,
    ELFToolchainMarker,
)


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()
    elf.get_section_by_name.return_value = None
    elf.iter_sections.return_value = []
    return elf


def test_elftoolchain_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFToolchainAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_empty_elf_has_no_toolchain(
    tmp_path: Path,
) -> None:
    """An ELF with no provenance markers should remain empty."""
    sample = tmp_path / "empty.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["toolchain_detected"] is False
    assert result.data["primary_compiler"] is None
    assert result.data["build_id"] is None
    assert result.data["markers"] == []
    assert result.findings == ()


def test_gcc_comment_is_detected(
    tmp_path: Path,
) -> None:
    """GCC metadata from .comment should be detected."""
    sample = tmp_path / "gcc.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=(
                ("GCC: (GNU) 16.1.1 20260625",),
                0,
            ),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["toolchain_detected"] is True
    assert result.data["gcc_detected"] is True
    assert result.data["clang_detected"] is False
    assert result.data["primary_compiler"] == "GCC"
    assert result.data["compiler_version"] == "16.1.1"
    assert result.data["comment_section_present"] is True
    assert result.data["comment_entry_count"] == 1


def test_clang_comment_is_detected(
    tmp_path: Path,
) -> None:
    """Clang metadata from .comment should be detected."""
    sample = tmp_path / "clang.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=(
                ("clang version 20.1.4",),
                0,
            ),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["clang_detected"] is True
    assert result.data["primary_compiler"] == "Clang"
    assert result.data["compiler_version"] == "20.1.4"


def test_binary_string_gcc_fallback(
    tmp_path: Path,
) -> None:
    """Binary strings should provide compiler fallback evidence."""
    sample = tmp_path / "gcc-fallback.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 0),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("GCC: (GNU) 15.2.1",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["gcc_detected"] is True
    assert result.data["primary_compiler"] == "GCC"
    assert result.data["compiler_version"] == "15.2.1"


def test_binary_string_clang_fallback(
    tmp_path: Path,
) -> None:
    """Binary strings should provide Clang fallback evidence."""
    sample = tmp_path / "clang-fallback.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 0),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("clang version 19.1.7",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["clang_detected"] is True
    assert result.data["primary_compiler"] == "Clang"
    assert result.data["compiler_version"] == "19.1.7"


def test_comment_compiler_has_priority_over_binary_strings(
    tmp_path: Path,
) -> None:
    """High-confidence .comment metadata should remain primary."""
    sample = tmp_path / "priority.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=(
                ("GCC: (GNU) 16.1.1",),
                0,
            ),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("clang version 20.1.0",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["gcc_detected"] is True
    assert result.data["clang_detected"] is True
    assert result.data["primary_compiler"] == "GCC"
    assert result.data["compiler_version"] == "16.1.1"


def test_build_id_is_preserved(
    tmp_path: Path,
) -> None:
    """GNU build IDs should be included as provenance evidence."""
    sample = tmp_path / "build-id.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._build_id",
            return_value=(
                "0123456789abcdef",
                0,
            ),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["build_id"] == "0123456789abcdef"
    assert result.data["toolchain_detected"] is True

    assert any(marker["category"] == "build-id" for marker in result.data["markers"])


def test_build_id_only_still_detects_provenance(
    tmp_path: Path,
) -> None:
    """Build ID alone should make provenance available."""
    sample = tmp_path / "build-only.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 0),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._build_id",
            return_value=(
                "deadbeef",
                0,
            ),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["toolchain_detected"] is True
    assert result.data["primary_compiler"] is None
    assert result.data["build_id"] == "deadbeef"


def test_rust_markers_are_detected(
    tmp_path: Path,
) -> None:
    """Rust runtime markers should identify Rust binaries."""
    sample = tmp_path / "rust.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(
                "rustc 1.88.0",
                "core::panicking",
            ),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["rust_detected"] is True
    assert result.data["language"] == "Rust"
    assert result.data["runtime"] == "Rust standard runtime"
    assert result.data["language_marker_count"] >= 1


def test_go_markers_are_detected(
    tmp_path: Path,
) -> None:
    """Go runtime markers should identify Go binaries."""
    sample = tmp_path / "go.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(
                "Go build ID: ABCDEF",
                "runtime.main",
            ),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["go_detected"] is True
    assert result.data["language"] == "Go"
    assert result.data["runtime"] == "Go runtime"


def test_go_version_marker_is_detected(
    tmp_path: Path,
) -> None:
    """Standalone Go version markers should be recognized."""
    sample = tmp_path / "go-version.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("go1.24.3",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["go_detected"] is True
    assert result.data["runtime_marker_count"] >= 1


def test_lld_linker_is_detected(
    tmp_path: Path,
) -> None:
    """LLD linker metadata should be normalized."""
    sample = tmp_path / "lld.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("LLD 20.1.4",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["linker"] == "LLD"
    assert result.data["linker_version"] == "20.1.4"
    assert result.data["linker_marker_count"] == 1


def test_gnu_ld_is_detected(
    tmp_path: Path,
) -> None:
    """GNU ld metadata should be normalized."""
    sample = tmp_path / "gnu-ld.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=("GNU ld (GNU Binutils) 2.44",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["linker"] == "GNU ld"
    assert result.data["linker_version"] == "2.44"


def test_lto_marker_is_detected(
    tmp_path: Path,
) -> None:
    """LTO markers should be surfaced."""
    sample = tmp_path / "lto.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(".gnu.lto_main.42",),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["lto_detected"] is True

    assert any(marker["category"] == "build" for marker in result.data["markers"])


def test_duplicate_markers_are_suppressed() -> None:
    """Exact duplicate provenance markers should not be duplicated."""
    from analyzers.elftoolchain.analyzer import _add_marker

    markers: list[ELFToolchainMarker] = []

    _add_marker(
        markers,
        category="compiler",
        value="GCC 16.1.1",
        source=".comment",
        confidence=95,
    )

    _add_marker(
        markers,
        category="compiler",
        value="GCC 16.1.1",
        source=".comment",
        confidence=95,
    )

    assert len(markers) == 1


def test_same_marker_from_different_sources_is_preserved() -> None:
    """Same evidence from distinct sources should remain separate."""
    from analyzers.elftoolchain.analyzer import _add_marker

    markers: list[ELFToolchainMarker] = []

    _add_marker(
        markers,
        category="compiler",
        value="GCC 16.1.1",
        source=".comment",
        confidence=95,
    )

    _add_marker(
        markers,
        category="compiler",
        value="GCC 16.1.1",
        source="binary-strings",
        confidence=70,
    )

    assert len(markers) == 2


def test_comment_malformed_count_is_preserved(
    tmp_path: Path,
) -> None:
    """Malformed .comment parsing should be counted."""
    sample = tmp_path / "comment-error.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 2),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._build_id",
            return_value=(None, 0),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 2


def test_note_malformed_count_is_preserved(
    tmp_path: Path,
) -> None:
    """Malformed note parsing should be counted."""
    sample = tmp_path / "note-error.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 0),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._build_id",
            return_value=(None, 3),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 3


def test_malformed_counts_are_aggregated(
    tmp_path: Path,
) -> None:
    """Malformed comment and note counts should be combined."""
    sample = tmp_path / "malformed.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elftoolchain.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elftoolchain.analyzer._comment_entries",
            return_value=((), 2),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._build_id",
            return_value=(None, 3),
        ),
        patch(
            "analyzers.elftoolchain.analyzer._scan_binary_strings",
            return_value=(),
        ),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 5


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elftoolchain.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

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
        "analyzers.elftoolchain.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFToolchainAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ELFToolchainAnalyzer()

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
    analyzer = ELFToolchainAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
