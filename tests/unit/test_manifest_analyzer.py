"""Tests for Astra PE application-manifest analysis."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pefile

from analyzers.common import Analyzer
from analyzers.manifest import ManifestAnalyzer
from packages.schemas import AnalysisStatus


def _resource_tree(blob: bytes) -> MagicMock:
    """Create a mocked PE resource tree containing one manifest."""
    language_entry = MagicMock()
    language_entry.data.struct.OffsetToData = 0x2000
    language_entry.data.struct.Size = len(blob)

    name_entry = MagicMock()
    name_entry.directory.entries = [language_entry]

    type_entry = MagicMock()
    type_entry.id = 24
    type_entry.directory.entries = [name_entry]

    resources = MagicMock()
    resources.entries = [type_entry]

    return resources


def _mock_pe(blob: bytes | None) -> MagicMock:
    """Create a representative mocked PE."""
    pe = MagicMock()

    if blob is None:
        pe.DIRECTORY_ENTRY_RESOURCE = None
    else:
        pe.DIRECTORY_ENTRY_RESOURCE = _resource_tree(blob)
        pe.get_data.return_value = blob

    return pe


def test_manifest_analyzer_contract() -> None:
    """The analyzer should satisfy Astra's analyzer protocol."""
    analyzer = ManifestAnalyzer()

    assert isinstance(analyzer, Analyzer)
    assert analyzer.supports("pe") is True
    assert analyzer.supports("elf") is False


def test_pe_without_manifest_returns_empty_result(
    tmp_path: Path,
) -> None:
    """A PE without RT_MANIFEST should return an empty result."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(None)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["manifest_present"] is False
    assert result.data["manifest_count"] == 0
    assert result.findings == ()


def test_require_administrator_manifest_is_normalized(
    tmp_path: Path,
) -> None:
    """Administrator execution level should be normalized without a finding."""
    sample = tmp_path / "installer.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel
          level="requireAdministrator"
          uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["manifest_present"] is True
    assert result.data["requested_execution_level"] == "requireAdministrator"
    assert result.data["requires_administrator"] is True
    assert result.data["ui_access"] is False
    assert result.findings == ()


def test_ui_access_generates_finding(
    tmp_path: Path,
) -> None:
    """uiAccess=true should generate a security-relevant finding."""
    sample = tmp_path / "uiaccess.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel
          level="asInvoker"
          uiAccess="true"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["ui_access"] is True

    assert any(finding.title == "Manifest enables UIAccess" for finding in result.findings)


def test_auto_elevate_generates_finding(
    tmp_path: Path,
) -> None:
    """autoElevate=true should generate a finding."""
    sample = tmp_path / "autoelevate.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <autoElevate>true</autoElevate>
    </windowsSettings>
  </application>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["auto_elevate"] is True

    assert any(
        finding.title == "Manifest requests automatic elevation" for finding in result.findings
    )


def test_admin_and_ui_access_combination_generates_finding(
    tmp_path: Path,
) -> None:
    """Administrator + UIAccess should generate the combination finding."""
    sample = tmp_path / "sensitive.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel
          level="requireAdministrator"
          uiAccess="true"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    titles = {finding.title for finding in result.findings}

    assert "Manifest enables UIAccess" in titles
    assert "Manifest combines administrator elevation with UIAccess" in titles


def test_dependency_extraction_ignores_root_identity(
    tmp_path: Path,
) -> None:
    """Only dependentAssembly identities should count as dependencies."""
    sample = tmp_path / "dependency.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <assemblyIdentity
      name="Example.Root"
      version="1.0.0.0"
      type="win32"/>

  <dependency>
    <dependentAssembly>
      <assemblyIdentity
          name="Microsoft.Windows.Common-Controls"
          version="6.0.0.0"
          processorArchitecture="*"
          publicKeyToken="6595b64144ccf1df"
          type="win32"/>
    </dependentAssembly>
  </dependency>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["dependency_count"] == 1
    assert result.data["dependencies"][0]["name"] == "Microsoft.Windows.Common-Controls"


def test_supported_os_entries_are_collected(
    tmp_path: Path,
) -> None:
    """supportedOS GUIDs should be normalized."""
    sample = tmp_path / "compat.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{11111111-1111-1111-1111-111111111111}"/>
      <supportedOS Id="{22222222-2222-2222-2222-222222222222}"/>
    </application>
  </compatibility>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.data["supported_os_count"] == 2


def test_dpi_and_long_path_settings_are_detected(
    tmp_path: Path,
) -> None:
    """Windows settings should be normalized."""
    sample = tmp_path / "settings.exe"
    sample.write_bytes(b"MZ")

    blob = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware>true</dpiAware>
      <longPathAware>true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"""

    pe = _mock_pe(blob)

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.data["dpi_aware"] is True
    assert result.data["long_path_aware"] is True


def test_malformed_xml_generates_finding(
    tmp_path: Path,
) -> None:
    """Malformed manifest XML should generate a finding."""
    sample = tmp_path / "malformed.exe"
    sample.write_bytes(b"MZ")

    pe = _mock_pe(b"<assembly><broken>")

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        return_value=pe,
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.COMPLETED
    assert result.data["malformed"] is True

    assert any(
        finding.title == "Malformed PE application manifest detected" for finding in result.findings
    )


def test_invalid_pe_returns_failed_result(
    tmp_path: Path,
) -> None:
    """Invalid PE files should return a failed result."""
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"invalid")

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        side_effect=pefile.PEFormatError("Invalid PE sample"),
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.FAILED
    assert result.errors
    assert result.errors[0].recoverable is False


def test_unexpected_parser_error_returns_partial_result(
    tmp_path: Path,
) -> None:
    """Unexpected parser failures should return partial."""
    sample = tmp_path / "partial.exe"
    sample.write_bytes(b"MZ")

    with patch(
        "analyzers.manifest.analyzer.pefile.PE",
        side_effect=RuntimeError("Unexpected parser failure"),
    ):
        result = ManifestAnalyzer().analyze(sample)

    assert result.status is AnalysisStatus.PARTIAL
    assert result.errors
    assert result.errors[0].recoverable is True


def test_missing_file_raises(
    tmp_path: Path,
) -> None:
    """Missing samples should raise FileNotFoundError."""
    analyzer = ManifestAnalyzer()

    try:
        analyzer.analyze(tmp_path / "missing.exe")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("FileNotFoundError was not raised")


def test_directory_is_rejected(
    tmp_path: Path,
) -> None:
    """Directories should not be accepted."""
    analyzer = ManifestAnalyzer()

    try:
        analyzer.analyze(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError was not raised")
