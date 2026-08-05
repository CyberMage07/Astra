"""Tests for Astra PE load-configuration analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.loadconfig import LoadConfigAnalyzer
from packages.schemas import AnalysisStatus

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000


def _mock_pe(
    *,
    load_config_present: bool,
    machine: int = IMAGE_FILE_MACHINE_AMD64,
    image_base: int = 0x140000000,
    size_of_image: int = 0x100000,
    dll_characteristics: int = 0,
    structure: MagicMock | None = None,
) -> MagicMock:
    """Create a representative mocked PE object."""
    pe = MagicMock()

    pe.FILE_HEADER.Machine = machine
    pe.OPTIONAL_HEADER.ImageBase = image_base
    pe.OPTIONAL_HEADER.SizeOfImage = size_of_image
    pe.OPTIONAL_HEADER.DllCharacteristics = dll_characteristics

    if load_config_present:
        directory = MagicMock()
        directory.struct = structure or _mock_load_config_structure(image_base=image_base)
        pe.DIRECTORY_ENTRY_LOAD_CONFIG = directory
    else:
        del pe.DIRECTORY_ENTRY_LOAD_CONFIG

    return pe


def _mock_load_config_structure(
    *,
    image_base: int = 0x140000000,
    size: int = 320,
    security_cookie: int | None = None,
    guard_flags: int = 0,
    guard_cf_check_function: int | None = None,
    guard_cf_dispatch_function: int | None = None,
    guard_cf_function_table: int | None = None,
    guard_cf_function_count: int = 0,
    seh_handler_table: int | None = None,
    seh_handler_count: int = 0,
    dynamic_value_reloc_table: int | None = None,
    code_integrity_present: bool = False,
) -> MagicMock:
    """Create a representative load-config structure."""
    structure = MagicMock()

    structure.Size = size
    structure.TimeDateStamp = 0
    structure.MajorVersion = 0
    structure.MinorVersion = 0

    structure.SecurityCookie = security_cookie if security_cookie is not None else 0
    structure.GuardFlags = guard_flags
    structure.GuardCFCheckFunctionPointer = (
        guard_cf_check_function if guard_cf_check_function is not None else 0
    )
    structure.GuardCFDispatchFunctionPointer = (
        guard_cf_dispatch_function if guard_cf_dispatch_function is not None else 0
    )
    structure.GuardCFFunctionTable = (
        guard_cf_function_table if guard_cf_function_table is not None else 0
    )
    structure.GuardCFFunctionCount = guard_cf_function_count

    structure.SEHandlerTable = seh_handler_table if seh_handler_table is not None else 0
    structure.SEHandlerCount = seh_handler_count

    structure.DynamicValueRelocTable = (
        dynamic_value_reloc_table if dynamic_value_reloc_table is not None else 0
    )

    code_integrity = MagicMock()
    code_integrity.Flags = 1 if code_integrity_present else 0
    code_integrity.Catalog = 0
    code_integrity.CatalogOffset = 0
    code_integrity.Reserved = 0

    structure.CodeIntegrity = code_integrity

    return structure


def test_loadconfig_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = LoadConfigAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_load_config_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without load-config data should return an empty result."""
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        load_config_present=False,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["load_config_present"] is False
    assert result.data["size"] == 0
    assert result.data["security_cookie_present"] is False
    assert result.data["control_flow_guard_enabled"] is False
    assert result.data["safe_seh_present"] is False
    assert result.data["malformed"] is False
    assert result.findings == ()


def test_security_cookie_is_detected(
    tmp_path: Path,
) -> None:
    """A valid security-cookie pointer should be normalized."""
    sample = tmp_path / "cookie.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000

    structure = _mock_load_config_structure(
        image_base=image_base,
        security_cookie=image_base + 0x2000,
    )

    pe = _mock_pe(
        load_config_present=True,
        image_base=image_base,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["load_config_present"] is True
    assert result.data["security_cookie_present"] is True
    assert result.data["security_cookie"] == image_base + 0x2000
    assert result.data["invalid_pointer_count"] == 0
    assert result.data["malformed"] is False


def test_control_flow_guard_is_detected_from_dll_characteristics(
    tmp_path: Path,
) -> None:
    """CFG should be detected from DLL characteristics."""
    sample = tmp_path / "cfg-dll.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        load_config_present=True,
        dll_characteristics=(IMAGE_DLLCHARACTERISTICS_GUARD_CF),
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["control_flow_guard_enabled"] is True


def test_control_flow_guard_is_detected_from_guard_flags(
    tmp_path: Path,
) -> None:
    """CFG should be detected from load-config GuardFlags."""
    sample = tmp_path / "cfg-flags.exe"
    sample.write_bytes(b"MZ")

    structure = _mock_load_config_structure(
        guard_flags=0x00000100 | 0x00000400,
        guard_cf_function_count=12,
    )

    pe = _mock_pe(
        load_config_present=True,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["control_flow_guard_enabled"] is True
    assert result.data["guard_cf_function_count"] == 12
    assert result.data["guard_flag_names"] == [
        "CF_INSTRUMENTED",
        "CF_FUNCTION_TABLE_PRESENT",
    ]


def test_safe_seh_is_detected_for_32_bit_pe(
    tmp_path: Path,
) -> None:
    """SafeSEH should be detected for 32-bit PE files."""
    sample = tmp_path / "safeseh.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x400000

    structure = _mock_load_config_structure(
        image_base=image_base,
        seh_handler_table=image_base + 0x3000,
        seh_handler_count=5,
    )

    pe = _mock_pe(
        load_config_present=True,
        machine=IMAGE_FILE_MACHINE_I386,
        image_base=image_base,
        size_of_image=0x100000,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["safe_seh_applicable"] is True
    assert result.data["safe_seh_present"] is True
    assert result.data["seh_handler_count"] == 5
    assert result.findings == ()


def test_missing_safe_seh_generates_info_finding(
    tmp_path: Path,
) -> None:
    """A 32-bit PE without SafeSEH should produce an info finding."""
    sample = tmp_path / "without-safeseh.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        load_config_present=True,
        machine=IMAGE_FILE_MACHINE_I386,
        image_base=0x400000,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["safe_seh_applicable"] is True
    assert result.data["safe_seh_present"] is False

    assert any(finding.title == "SafeSEH is not enabled" for finding in result.findings)


def test_safeseh_is_not_applicable_to_64_bit_pe(
    tmp_path: Path,
) -> None:
    """SafeSEH should not be treated as applicable to x64 PE files."""
    sample = tmp_path / "x64.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        load_config_present=True,
        machine=IMAGE_FILE_MACHINE_AMD64,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["safe_seh_applicable"] is False
    assert result.data["safe_seh_present"] is False
    assert not any(finding.title == "SafeSEH is not enabled" for finding in result.findings)


def test_code_integrity_metadata_is_detected(
    tmp_path: Path,
) -> None:
    """Populated code-integrity metadata should be detected."""
    sample = tmp_path / "code-integrity.exe"
    sample.write_bytes(b"MZ")

    structure = _mock_load_config_structure(
        code_integrity_present=True,
    )

    pe = _mock_pe(
        load_config_present=True,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["code_integrity_present"] is True


def test_invalid_pointer_marks_load_config_malformed(
    tmp_path: Path,
) -> None:
    """Pointers outside the image should mark the structure malformed."""
    sample = tmp_path / "invalid-pointer.exe"
    sample.write_bytes(b"MZ")

    image_base = 0x140000000

    structure = _mock_load_config_structure(
        image_base=image_base,
        security_cookie=image_base + 0x500000,
    )

    pe = _mock_pe(
        load_config_present=True,
        image_base=image_base,
        size_of_image=0x100000,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["invalid_pointer_count"] == 1
    assert result.data["malformed"] is True

    assert any(
        finding.title == "Malformed PE load configuration detected" for finding in result.findings
    )


def test_zero_size_marks_load_config_malformed(
    tmp_path: Path,
) -> None:
    """A zero-sized load-config directory should be malformed."""
    sample = tmp_path / "zero-size.exe"
    sample.write_bytes(b"MZ")

    structure = _mock_load_config_structure(
        size=0,
    )

    pe = _mock_pe(
        load_config_present=True,
        structure=structure,
    )

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed"] is True


def test_missing_load_config_structure_is_malformed(
    tmp_path: Path,
) -> None:
    """A directory without a structure should be malformed."""
    sample = tmp_path / "missing-struct.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(
        load_config_present=True,
    )
    pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct = None

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["load_config_present"] is True
    assert result.data["malformed"] is True


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser errors should return a partial result."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.loadconfig.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = LoadConfigAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = LoadConfigAnalyzer()

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
    analyzer = LoadConfigAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
