"""Tests for Astra load-configuration CLI output."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def test_loadconfig_command_displays_result(
    tmp_path: Path,
) -> None:
    """The loadconfig command should display mitigation data."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    result = AnalysisResult(
        analyzer="loadconfig",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=5,
        data={
            "load_config_present": True,
            "size": 320,
            "timestamp": 0,
            "major_version": 0,
            "minor_version": 0,
            "security_cookie": 0x140010000,
            "security_cookie_present": True,
            "guard_flags": 0x100,
            "guard_flag_names": [
                "CF_INSTRUMENTED",
            ],
            "control_flow_guard_enabled": True,
            "guard_cf_check_function": None,
            "guard_cf_dispatch_function": None,
            "guard_cf_function_table": None,
            "guard_cf_function_count": 0,
            "seh_handler_table": None,
            "seh_handler_count": 0,
            "safe_seh_present": False,
            "safe_seh_applicable": False,
            "dynamic_value_reloc_table": None,
            "code_integrity_present": False,
            "malformed": False,
            "invalid_pointer_count": 0,
        },
    )

    with patch(
        "apps.cli.main.LoadConfigAnalyzer.analyze",
        return_value=result,
    ):
        cli_result = runner.invoke(
            app,
            ["loadconfig", str(sample)],
        )

    assert cli_result.exit_code == 0
    assert "PE Load Configuration Analysis" in cli_result.stdout
    assert "Security cookie" in cli_result.stdout
    assert "Control Flow Guard" in cli_result.stdout
    assert "CF_INSTRUMENTED" in cli_result.stdout


def test_loadconfig_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """The loadconfig command should reject missing samples."""
    sample = tmp_path / "missing.exe"

    cli_result = runner.invoke(
        app,
        ["loadconfig", str(sample)],
    )

    assert cli_result.exit_code == 1
    assert "File does not exist" in cli_result.stdout
