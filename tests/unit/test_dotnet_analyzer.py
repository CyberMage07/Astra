"""Tests for Astra .NET CLR analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzers.common import Analyzer
from analyzers.dotnet import DotNetAnalyzer
from packages.schemas import AnalysisStatus


def _mock_rows(*rows: MagicMock) -> MagicMock:
    """Create a mocked metadata table."""
    table = MagicMock()
    table.rows = list(rows)
    return table


def _mock_dotnet_pe(
    *,
    dotnet_present: bool = True,
    flags: int = 1,
    entry_point: int = 0x06000001,
    metadata_present: bool = True,
    assembly_name: str = "Sample",
    module_name: str = "Sample.exe",
    pinvoke_count: int = 0,
) -> MagicMock:
    """Create representative mocked dnfile output."""
    pe = MagicMock()

    if not dotnet_present:
        pe.net = None
        return pe

    net = MagicMock()
    pe.net = net

    net.struct.Flags = flags
    net.struct.cb = 72
    net.struct.EntryPointTokenOrRva = entry_point
    net.struct.MajorRuntimeVersion = 2
    net.struct.MinorRuntimeVersion = 5

    if metadata_present:
        metadata = MagicMock()
        net.metadata = metadata

        metadata.struct.Signature = 0x424A5342
        metadata.struct.Version = b"v4.0.30319\x00"

        stream = MagicMock()
        stream.name = b"#~"
        stream.file_offset = 512
        stream.size = 4096

        metadata.streams_list = [stream]
    else:
        net.metadata = None

    tables = MagicMock()
    net.mdtables = tables

    assembly = MagicMock()
    assembly.Name = assembly_name
    assembly.Culture = None
    assembly.MajorVersion = 1
    assembly.MinorVersion = 2
    assembly.BuildNumber = 3
    assembly.RevisionNumber = 4

    tables.Assembly = _mock_rows(assembly)

    module = MagicMock()
    module.Name = module_name
    tables.Module = _mock_rows(module)

    reference = MagicMock()
    reference.Name = "System.Runtime"
    reference.Culture = None
    reference.MajorVersion = 8
    reference.MinorVersion = 0
    reference.BuildNumber = 0
    reference.RevisionNumber = 0

    tables.AssemblyRef = _mock_rows(reference)

    tables.TypeDef = _mock_rows(
        MagicMock(),
        MagicMock(),
    )

    tables.MethodDef = _mock_rows(
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    tables.MemberRef = _mock_rows(
        MagicMock(),
    )

    tables.ImplMap = _mock_rows(*(MagicMock() for _ in range(pinvoke_count)))

    return pe


def test_dotnet_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = DotNetAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_native_pe_returns_dotnet_false(
    tmp_path: Path,
) -> None:
    """Native PE files should return dotnet_present false."""
    sample = tmp_path / "native.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        dotnet_present=False,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dotnet_present"] is False
    assert result.findings == ()


def test_managed_pe_metadata_is_normalized(
    tmp_path: Path,
) -> None:
    """Managed CLR metadata should be normalized."""
    sample = tmp_path / "managed.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe()

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dotnet_present"] is True
    assert result.data["clr_header_present"] is True
    assert result.data["metadata_present"] is True

    assert result.data["clr_header_size"] == 72
    assert result.data["runtime_version"] == "v4.0.30319"

    assert result.data["clr_flags"] == 1
    assert result.data["clr_flag_names"] == [
        "ILONLY",
    ]
    assert result.data["il_only"] is True

    assert result.data["entry_point_token"] == 0x06000001
    assert result.data["entry_point_rva"] is None

    assert result.data["metadata_signature"] == 0x424A5342
    assert result.data["metadata_version"] == "v4.0.30319"

    assert result.data["stream_count"] == 1
    assert result.data["streams"][0]["name"] == "#~"

    assert result.data["assembly_name"] == "Sample"
    assert result.data["assembly_version"] == "1.2.3.4"
    assert result.data["module_name"] == "Sample.exe"

    assert result.data["assembly_reference_count"] == 1
    assert result.data["assembly_references"][0]["name"] == "System.Runtime"

    assert result.data["type_definition_count"] == 2
    assert result.data["method_definition_count"] == 3
    assert result.data["member_reference_count"] == 1


def test_native_entry_point_uses_rva(
    tmp_path: Path,
) -> None:
    """Native CLR entry points should be represented as RVAs."""
    sample = tmp_path / "native-entry.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        flags=0x10,
        entry_point=0x2000,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["native_entry_point"] is True
    assert result.data["entry_point_token"] is None
    assert result.data["entry_point_rva"] == 0x2000


def test_mixed_mode_generates_info_finding(
    tmp_path: Path,
) -> None:
    """Non-IL-only managed files should be identified as mixed mode."""
    sample = tmp_path / "mixed.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        flags=0,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["mixed_mode"] is True

    assert any(finding.title == "Mixed-mode .NET assembly detected" for finding in result.findings)


def test_strong_name_flag_is_detected(
    tmp_path: Path,
) -> None:
    """Strong-name signing flags should be normalized."""
    sample = tmp_path / "signed.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        flags=0x01 | 0x08,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["strong_name_signed"] is True
    assert "STRONGNAMESIGNED" in result.data["clr_flag_names"]


def test_32bit_flags_are_detected(
    tmp_path: Path,
) -> None:
    """CLR 32-bit flags should be normalized."""
    sample = tmp_path / "x86.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        flags=0x01 | 0x02 | 0x20000,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["thirty_two_bit_required"] is True
    assert result.data["thirty_two_bit_preferred"] is True


def test_pinvoke_is_counted_and_reported(
    tmp_path: Path,
) -> None:
    """P/Invoke metadata should be counted and surfaced."""
    sample = tmp_path / "pinvoke.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        pinvoke_count=2,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["pinvoke_method_count"] == 2

    assert any(finding.title == ".NET assembly uses native P/Invoke" for finding in result.findings)


def test_missing_metadata_is_malformed(
    tmp_path: Path,
) -> None:
    """CLR headers without metadata should be treated as malformed."""
    sample = tmp_path / "malformed.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe(
        metadata_present=False,
    )

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dotnet_present"] is True
    assert result.data["metadata_present"] is False
    assert result.data["malformed_metadata"] is True

    assert any(finding.title == "Malformed .NET metadata detected" for finding in result.findings)


def test_assembly_reference_is_normalized(
    tmp_path: Path,
) -> None:
    """AssemblyRef rows should include normalized versions."""
    sample = tmp_path / "references.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_dotnet_pe()

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        return_value=pe,
    ):
        result = DotNetAnalyzer().analyze(sample)

    reference = result.data["assembly_references"][0]

    assert reference["name"] == "System.Runtime"
    assert reference["major_version"] == 8
    assert reference["minor_version"] == 0
    assert reference["version"] == "8.0.0.0"


def test_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Parser failures should return a structured partial result."""
    sample = tmp_path / "broken.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.dotnet.analyzer.dnfile.dnPE",
        side_effect=RuntimeError("CLR parser failure"),
    ):
        result = DotNetAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = DotNetAnalyzer()

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
    analyzer = DotNetAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
