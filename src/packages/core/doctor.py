"""Environment diagnostics for Astra."""

import importlib.util
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from packages.config import AstraSettings


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """Result of a single Astra environment check."""

    component: str
    available: bool
    details: str
    required: bool = True


def _command_check(
    command: str,
    component: str,
    *,
    required: bool = True,
) -> DoctorCheck:
    """Check whether an executable exists in PATH."""
    executable = shutil.which(command)

    if executable is None:
        return DoctorCheck(
            component=component,
            available=False,
            details=f"{command} not found",
            required=required,
        )

    return DoctorCheck(
        component=component,
        available=True,
        details=executable,
        required=required,
    )


def _module_check(
    module: str,
    component: str,
    *,
    required: bool = True,
) -> DoctorCheck:
    """Check whether a Python module can be imported."""
    available = importlib.util.find_spec(module) is not None

    return DoctorCheck(
        component=component,
        available=available,
        details=f"Python module: {module}",
        required=required,
    )


def run_doctor_checks(settings: AstraSettings) -> list[DoctorCheck]:
    """Run Astra environment diagnostics."""
    storage_root: Path = settings.resolved_storage_root

    return [
        DoctorCheck(
            component="Python runtime",
            available=sys.version_info[:2] == (3, 12),
            details=sys.version.split()[0],
        ),
        DoctorCheck(
            component="Storage directory",
            available=storage_root.exists() and storage_root.is_dir(),
            details=str(storage_root),
        ),
        _module_check("magic", "File identification"),
        _module_check("pydantic", "Configuration validation"),
        _module_check("rich", "Terminal rendering"),
        _command_check("file", "libmagic command"),
        _command_check("yara", "YARA engine", required=False),
        _command_check("podman", "Podman runtime", required=False),
        _command_check("7z", "Archive utility", required=False),
        _command_check("sqlite3", "SQLite CLI", required=False),
    ]


def doctor_passed(checks: list[DoctorCheck]) -> bool:
    """Return whether all required checks passed."""
    return all(check.available for check in checks if check.required)
