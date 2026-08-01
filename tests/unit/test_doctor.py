"""Tests for Astra environment diagnostics."""

from pathlib import Path

from packages.config import AstraSettings
from packages.core import DoctorCheck, doctor_passed, run_doctor_checks


def test_doctor_passes_when_required_checks_succeed() -> None:
    """Optional failures must not fail the complete diagnostic."""
    checks = [
        DoctorCheck("Required", True, "ready"),
        DoctorCheck("Optional", False, "missing", required=False),
    ]

    assert doctor_passed(checks) is True


def test_doctor_fails_when_required_check_fails() -> None:
    """A failed required component must fail the diagnostic."""
    checks = [
        DoctorCheck("Required", False, "missing"),
    ]

    assert doctor_passed(checks) is False


def test_environment_checks_return_results(tmp_path: Path) -> None:
    """The diagnostic runner should return populated checks."""
    settings = AstraSettings(project_root=tmp_path)
    settings.ensure_directories()

    checks = run_doctor_checks(settings)

    assert checks
    assert any(check.component == "Python runtime" for check in checks)
    assert any(check.component == "Storage directory" for check in checks)
