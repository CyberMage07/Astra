"""Tests for Astra ELF GNU symbol-versioning analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.elfversioning import ELFVersioningAnalyzer
from packages.schemas import AnalysisStatus


def _mock_elf() -> MagicMock:
    """Create a minimal ELF parser fixture."""
    elf = MagicMock()

    elf.get_section_by_name.return_value = None

    return elf


def test_elfversioning_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer contract."""
    analyzer = ELFVersioningAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("elf") is True
    assert analyzer.supports("pe") is False


def test_no_versioning_returns_empty_result(
    tmp_path: Path,
) -> None:
    """An ELF without GNU version metadata should remain clean."""
    sample = tmp_path / "noversion.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with patch(
        "analyzers.elfversioning.analyzer._load_elf",
        return_value=elf,
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["versioning_present"] is False
    assert result.data["required_version_count"] == 0
    assert result.data["defined_version_count"] == 0
    assert result.data["versioned_symbol_count"] == 0
    assert result.findings == ()


def test_versioning_presence_flags_are_preserved(
    tmp_path: Path,
) -> None:
    """GNU versioning section presence should be surfaced."""
    sample = tmp_path / "presence.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    class DummyVerSymSection:
        """Dummy GNU version-symbol section."""

    class DummyVerNeedSection:
        """Dummy GNU version-requirement section."""

    versym = DummyVerSymSection()
    verneed = DummyVerNeedSection()

    def get_section(
        name: str,
    ) -> object | None:
        mapping: dict[
            str,
            object,
        ] = {
            ".gnu.version": versym,
            ".gnu.version_r": verneed,
        }

        return mapping.get(name)

    elf.get_section_by_name.side_effect = get_section

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer.GNUVerSymSection",
            DummyVerSymSection,
        ),
        patch(
            "analyzers.elfversioning.analyzer.GNUVerNeedSection",
            DummyVerNeedSection,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(
                (),
                {},
                0,
            ),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=(
                (),
                {},
                0,
            ),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=(
                (),
                0,
            ),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED

    assert result.data["versioning_present"] is True

    assert result.data["versym_present"] is True

    assert result.data["verneed_present"] is True

    assert result.data["verdef_present"] is False


def test_requirement_counts_are_preserved(
    tmp_path: Path,
) -> None:
    """Version requirements should be counted."""
    sample = tmp_path / "requirements.elf"

    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import (
        ELFSymbolVersionRequirement,
    )

    requirements = (
        ELFSymbolVersionRequirement(
            library="libc.so.6",
            version="GLIBC_2.34",
            version_index=2,
            hidden=False,
        ),
        ELFSymbolVersionRequirement(
            library="libc.so.6",
            version="GLIBC_2.38",
            version_index=3,
            hidden=False,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(
                requirements,
                {
                    2: (
                        "libc.so.6",
                        "GLIBC_2.34",
                    ),
                    3: (
                        "libc.so.6",
                        "GLIBC_2.38",
                    ),
                },
                0,
            ),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=(
                (),
                {},
                0,
            ),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=(
                (),
                0,
            ),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["required_library_count"] == 1

    assert result.data["required_version_count"] == 2

    assert result.data["glibc_version_count"] == 2

    assert result.data["highest_glibc_version"] == "GLIBC_2.38"


def test_multiple_required_libraries_are_counted(
    tmp_path: Path,
) -> None:
    """Different dependency libraries should be counted separately."""
    sample = tmp_path / "libraries.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionRequirement

    requirements = (
        ELFSymbolVersionRequirement(
            library="libc.so.6",
            version="GLIBC_2.34",
            version_index=2,
        ),
        ELFSymbolVersionRequirement(
            library="libcrypto.so.3",
            version="OPENSSL_3.0.0",
            version_index=3,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(requirements, {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["required_library_count"] == 2


def test_glibcxx_versions_are_counted(
    tmp_path: Path,
) -> None:
    """GLIBCXX ABI requirements should be counted."""
    sample = tmp_path / "glibcxx.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionRequirement

    requirements = (
        ELFSymbolVersionRequirement(
            library="libstdc++.so.6",
            version="GLIBCXX_3.4.29",
            version_index=2,
        ),
        ELFSymbolVersionRequirement(
            library="libstdc++.so.6",
            version="GLIBCXX_3.4.31",
            version_index=3,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(requirements, {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["glibcxx_version_count"] == 2
    assert result.data["highest_glibcxx_version"] == "GLIBCXX_3.4.31"


def test_cxxabi_versions_are_counted(
    tmp_path: Path,
) -> None:
    """CXXABI requirements should be counted."""
    sample = tmp_path / "cxxabi.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionRequirement

    requirements = (
        ELFSymbolVersionRequirement(
            library="libstdc++.so.6",
            version="CXXABI_1.3.13",
            version_index=2,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(requirements, {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["cxxabi_version_count"] == 1
    assert result.data["highest_cxxabi_version"] == "CXXABI_1.3.13"


def test_non_numeric_glibc_tag_does_not_affect_highest(
    tmp_path: Path,
) -> None:
    """GLIBC ABI marker tags should not become highest numeric versions."""
    sample = tmp_path / "abi-tag.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionRequirement

    requirements = (
        ELFSymbolVersionRequirement(
            library="libc.so.6",
            version="GLIBC_ABI_DT_RELR",
            version_index=2,
        ),
        ELFSymbolVersionRequirement(
            library="libc.so.6",
            version="GLIBC_2.38",
            version_index=3,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=(requirements, {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["glibc_version_count"] == 2
    assert result.data["highest_glibc_version"] == "GLIBC_2.38"


def test_defined_versions_are_counted(
    tmp_path: Path,
) -> None:
    """Defined GNU symbol versions should be preserved."""
    sample = tmp_path / "definitions.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionDefinition

    definitions = (
        ELFSymbolVersionDefinition(
            version="ASTRA_1.0",
            version_index=2,
        ),
        ELFSymbolVersionDefinition(
            version="ASTRA_2.0",
            version_index=3,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=(definitions, {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["defined_version_count"] == 2


def test_imported_and_exported_bindings_are_counted(
    tmp_path: Path,
) -> None:
    """Versioned imported/exported symbols should be distinguished."""
    sample = tmp_path / "bindings.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionBinding

    bindings = (
        ELFSymbolVersionBinding(
            symbol="memcpy",
            version="GLIBC_2.14",
            version_index=2,
            imported=True,
        ),
        ELFSymbolVersionBinding(
            symbol="astra_export",
            version="ASTRA_1.0",
            version_index=3,
            exported=True,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=(bindings, 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["versioned_symbol_count"] == 2
    assert result.data["imported_versioned_symbol_count"] == 1
    assert result.data["exported_versioned_symbol_count"] == 1


def test_hidden_binding_is_preserved(
    tmp_path: Path,
) -> None:
    """Hidden GNU version bindings should remain visible."""
    sample = tmp_path / "hidden.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    from packages.schemas import ELFSymbolVersionBinding

    bindings = (
        ELFSymbolVersionBinding(
            symbol="hidden_symbol",
            version="ASTRA_1.0",
            version_index=2,
            exported=True,
            hidden=True,
        ),
    )

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=(bindings, 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["bindings"][0]["hidden"] is True


def test_highest_version_is_numeric_not_lexicographic() -> None:
    """Version comparison should use numeric components."""
    from analyzers.elfversioning.analyzer import _highest_version

    versions = {
        "GLIBC_2.9",
        "GLIBC_2.10",
        "GLIBC_2.38",
    }

    assert _highest_version(versions) == "GLIBC_2.38"


def test_highest_version_handles_three_components() -> None:
    """Three-part GNU versions should compare correctly."""
    from analyzers.elfversioning.analyzer import _highest_version

    versions = {
        "GLIBC_2.3",
        "GLIBC_2.3.4",
        "GLIBC_2.4",
    }

    assert _highest_version(versions) == "GLIBC_2.4"


def test_highest_version_returns_none_for_non_numeric_tags() -> None:
    """Non-numeric ABI markers should not produce a highest version."""
    from analyzers.elfversioning.analyzer import _highest_version

    assert (
        _highest_version(
            {
                "GLIBC_ABI_DT_RELR",
            }
        )
        is None
    )


def test_malformed_requirement_metadata_generates_finding(
    tmp_path: Path,
) -> None:
    """Malformed requirement metadata should generate a finding."""
    sample = tmp_path / "malformed-requirement.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 2),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 2
    assert result.findings


def test_malformed_definition_metadata_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed version definitions should be counted."""
    sample = tmp_path / "malformed-definition.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 3),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 3


def test_malformed_binding_metadata_is_counted(
    tmp_path: Path,
) -> None:
    """Malformed version bindings should be counted."""
    sample = tmp_path / "malformed-binding.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 4),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 4


def test_malformed_counts_are_aggregated(
    tmp_path: Path,
) -> None:
    """Malformed counts from all version sources should be combined."""
    sample = tmp_path / "malformed-all.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 1),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 2),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 3),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.data["malformed_entry_count"] == 6


def test_clean_versioning_generates_no_findings(
    tmp_path: Path,
) -> None:
    """Normal symbol versioning should remain informational."""
    sample = tmp_path / "clean.elf"
    sample.write_bytes(b"\x7fELF")

    elf = _mock_elf()

    with (
        patch(
            "analyzers.elfversioning.analyzer._load_elf",
            return_value=elf,
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_requirements",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_definitions",
            return_value=((), {}, 0),
        ),
        patch(
            "analyzers.elfversioning.analyzer._extract_bindings",
            return_value=((), 0),
        ),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.findings == ()


def test_unexpected_parser_error_returns_partial(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should remain recoverable."""
    sample = tmp_path / "error.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "analyzers.elfversioning.analyzer._load_elf",
        side_effect=RuntimeError("unexpected parser error"),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

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
        "analyzers.elfversioning.analyzer._load_elf",
        side_effect=ValueError("Invalid ELF"),
    ):
        result = ELFVersioningAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing files should raise FileNotFoundError."""
    analyzer = ELFVersioningAnalyzer()

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
    analyzer = ELFVersioningAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
