"""Tests for Astra .NET CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_dotnet_command_displays_result(
    tmp_path: Path,
) -> None:
    """The dotnet command should display managed metadata."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="dotnet",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "dotnet_present": True,
            "clr_header_present": True,
            "metadata_present": True,
            "clr_header_size": 72,
            "runtime_version": "v4.0.30319",
            "clr_flags": 1,
            "clr_flag_names": ["ILONLY"],
            "il_only": True,
            "thirty_two_bit_required": False,
            "thirty_two_bit_preferred": False,
            "strong_name_signed": False,
            "native_entry_point": False,
            "mixed_mode": False,
            "entry_point_token": 0x06000001,
            "entry_point_rva": None,
            "metadata_signature": 0x424A5342,
            "metadata_version": "v4.0.30319",
            "stream_count": 1,
            "streams": [
                {
                    "name": "#~",
                    "offset": 512,
                    "size": 4096,
                }
            ],
            "assembly_name": "Sample",
            "assembly_version": "1.0.0.0",
            "assembly_culture": None,
            "module_name": "Sample.exe",
            "assembly_reference_count": 1,
            "assembly_references": [
                {
                    "name": "System.Runtime",
                    "major_version": 8,
                    "minor_version": 0,
                    "build_number": 0,
                    "revision_number": 0,
                    "culture": None,
                    "version": "8.0.0.0",
                }
            ],
            "type_definition_count": 2,
            "method_definition_count": 3,
            "member_reference_count": 1,
            "pinvoke_method_count": 0,
            "malformed_metadata": False,
        },
    )

    with patch(
        "apps.cli.main.DotNetAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["dotnet", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert ".NET CLR Analysis" in cli_result.stdout
    assert "Sample" in cli_result.stdout
    assert "v4.0.30319" in cli_result.stdout
    assert "System.Runtime" in cli_result.stdout
    assert "#~" in cli_result.stdout


def test_dotnet_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["dotnet", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
