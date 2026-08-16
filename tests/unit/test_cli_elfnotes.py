"""Tests for Astra ELF note CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from apps.cli.main import app
from packages.schemas import (
    AnalysisResult,
    AnalysisStatus,
)

runner = CliRunner()


def _result() -> AnalysisResult:
    """Return one completed ELF note result."""
    return AnalysisResult(
        analyzer="elfnotes",
        analyzer_version="0.1.0",
        status=AnalysisStatus.COMPLETED,
        duration_ms=2,
        data={
            "note_sections_present": True,
            "note_section_count": 3,
            "note_count": 3,
            "malformed_note_count": 0,
            "build_id_present": True,
            "build_id": "abcdef123456",
            "abi_tag_present": True,
            "abi_os": "Linux",
            "abi_major": 4,
            "abi_minor": 4,
            "abi_patch": 0,
            "gnu_property_present": True,
            "ibt_enabled": True,
            "shstk_enabled": True,
            "sections": [
                {
                    "name": ".note.gnu.property",
                    "note_count": 1,
                    "malformed_note_count": 0,
                    "notes": [
                        {
                            "section_name": ".note.gnu.property",
                            "owner": "GNU",
                            "note_type": "NT_GNU_PROPERTY_TYPE_0",
                            "description": None,
                            "build_id": None,
                            "abi_os": None,
                            "abi_major": None,
                            "abi_minor": None,
                            "abi_patch": None,
                            "gnu_property_type": ("GNU_PROPERTY_X86_FEATURE_1_AND"),
                            "gnu_property_value": "0x3",
                            "malformed": False,
                        }
                    ],
                }
            ],
        },
    )


def test_elfnotes_command_displays_result(
    tmp_path: Path,
) -> None:
    """CLI should display normalized ELF note metadata."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")

    with patch(
        "apps.cli.main.ELFNotesAnalyzer.analyze",
        return_value=_result(),
    ):
        result = runner.invoke(
            app,
            [
                "elfnotes",
                str(sample),
            ],
        )

    assert result.exit_code == 0
    assert "ELF Note and ABI Analysis" in result.stdout
    assert "abcdef123456" in result.stdout
    assert "Linux" in result.stdout
    assert "4.4.0" in result.stdout
    assert "GNU_PROPERTY_X86_FEATURE_1_AND" in result.stdout
    assert "0x3" in result.stdout


def test_elfnotes_command_rejects_missing_file(
    tmp_path: Path,
) -> None:
    """Missing files should be rejected."""
    sample = tmp_path / "missing.elf"

    result = runner.invoke(
        app,
        [
            "elfnotes",
            str(sample),
        ],
    )

    assert result.exit_code == 1
    assert "File does not exist" in result.stdout
