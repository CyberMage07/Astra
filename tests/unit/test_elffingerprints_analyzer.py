"""Tests for Astra ELF fingerprint analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elffingerprints import ELFFingerprintsAnalyzer
from packages.schemas import AnalysisStatus


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.iter_sections.return_value = []
    elf.get_section_by_name.return_value = None

    return elf


def test_elffingerprints_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFFingerprintsAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_empty_elf_returns_unavailable_fingerprint(
    tmp_path: Path,
) -> None:
    """An ELF with no usable sources should report unavailable."""
    sample = tmp_path / "empty.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elffingerprints.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["fingerprint_available"] is False
    assert result.data["imported_symbol_count"] == 0
    assert result.data["needed_library_count"] == 0
    assert result.data["section_count"] == 0
    assert result.data["source_count"] == 0
    assert result.data["combined_fingerprint"] is None
    assert result.findings == ()


def test_import_fingerprint_is_deterministic(
    tmp_path: Path,
) -> None:
    """Imported symbols should produce deterministic fingerprints."""
    sample = tmp_path / "imports.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=(
                "connect",
                "execve",
            ),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value=None,
        ),
    ):
        first = ELFFingerprintsAnalyzer().analyze(sample)
        second = ELFFingerprintsAnalyzer().analyze(sample)

    assert first.status is AnalysisStatus.COMPLETED
    assert second.status is AnalysisStatus.COMPLETED

    assert first.data["import_fingerprint"] == second.data["import_fingerprint"]
    assert first.data["combined_fingerprint"] == second.data["combined_fingerprint"]

    assert first.data["imported_symbol_count"] == 2
    assert first.data["source_count"] == 1


def test_library_fingerprint_is_generated(
    tmp_path: Path,
) -> None:
    """DT_NEEDED libraries should produce a stable fingerprint."""
    sample = tmp_path / "libraries.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=(
                "libc.so.6",
                "libcrypto.so.3",
            ),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value=None,
        ),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["fingerprint_available"] is True
    assert result.data["needed_library_count"] == 2
    assert result.data["library_fingerprint"] is not None
    assert result.data["source_count"] == 1


def test_section_fingerprint_is_generated(
    tmp_path: Path,
) -> None:
    """Section-layout descriptors should be fingerprinted."""
    sample = tmp_path / "sections.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(
                ".text:SHT_PROGBITS:6:4096",
                ".data:SHT_PROGBITS:3:512",
            ),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value=None,
        ),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["section_count"] == 2
    assert result.data["section_fingerprint"] is not None
    assert result.data["source_count"] == 1


def test_combined_fingerprint_uses_all_sources(
    tmp_path: Path,
) -> None:
    """Combined fingerprint should change when its sources change."""
    sample = tmp_path / "combined.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=("connect",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=("libc.so.6",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(".text:SHT_PROGBITS:6:4096",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value=None,
        ),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["source_count"] == 3
    assert result.data["import_fingerprint"] is not None
    assert result.data["library_fingerprint"] is not None
    assert result.data["section_fingerprint"] is not None
    assert result.data["combined_fingerprint"] is not None


def test_build_id_without_sources_is_available(
    tmp_path: Path,
) -> None:
    """Build-ID alone should make ELF identity information available."""
    sample = tmp_path / "build-id.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value="0123456789abcdef",
        ),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["fingerprint_available"] is True
    assert result.data["build_id"] == "0123456789abcdef"
    assert result.data["source_count"] == 0
    assert result.data["combined_fingerprint"] is None


def test_fingerprints_generate_no_findings(
    tmp_path: Path,
) -> None:
    """Fingerprint existence should not itself be suspicious."""
    sample = tmp_path / "benign.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elffingerprints.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_imports",
            return_value=("execve",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_libraries",
            return_value=("libc.so.6",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_sections",
            return_value=(".text:SHT_PROGBITS:6:128",),
        ),
        patch(
            "analyzers.elffingerprints.analyzer._extract_build_id",
            return_value=None,
        ),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.findings == ()


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elffingerprints.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

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
        "analyzers.elffingerprints.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFFingerprintsAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing files should raise FileNotFoundError."""
    analyzer = ELFFingerprintsAnalyzer()

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
    analyzer = ELFFingerprintsAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
