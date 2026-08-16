"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from analyzers.debug import DebugDirectoryAnalyzer
from analyzers.dotnet import DotNetAnalyzer
from analyzers.elf import ELFAnalyzer
from analyzers.elfsymbols import ELFSymbolsAnalyzer
from analyzers.embedded import EmbeddedAnalyzer
from analyzers.entropy import EntropyAnalyzer
from analyzers.exports import ExportsAnalyzer
from analyzers.filetype import identify_file
from analyzers.fingerprints import FingerprintsAnalyzer
from analyzers.importdirectories import ImportDirectoriesAnalyzer
from analyzers.ioc import IOCAnalyzer
from analyzers.loadconfig import LoadConfigAnalyzer
from analyzers.manifest import ManifestAnalyzer
from analyzers.metadata import MetadataAnalyzer
from analyzers.overlay import OverlayAnalyzer
from analyzers.packer import PackerAnalyzer
from analyzers.pe import PEAnalyzer
from analyzers.relocations import RelocationsAnalyzer
from analyzers.resources import ResourcesAnalyzer
from analyzers.richheader import RichHeaderAnalyzer
from analyzers.sections import SectionsAnalyzer
from analyzers.signature import SignatureAnalyzer
from analyzers.signatures import ImportAnalyzer
from analyzers.strings import StringsAnalyzer
from analyzers.tls import TLSAnalyzer
from analyzers.versioninfo import VersionInfoAnalyzer
from analyzers.yara import YaraAnalyzer
from packages.config import get_settings
from packages.core import AnalysisOrchestrator, doctor_passed, ingest_sample, run_doctor_checks
from packages.schemas import AnalysisStatus

app = typer.Typer(
    name="astra",
    help="Enterprise-oriented static and dynamic malware analysis platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _handle_path_error(error: FileNotFoundError | ValueError) -> None:
    """Display a clean CLI message for invalid sample paths."""
    if isinstance(error, FileNotFoundError):
        missing_path = error.filename or str(error)
        console.print(f"[bold red]Error:[/bold red] File does not exist: {missing_path}")
    else:
        console.print(f"[bold red]Error:[/bold red] {error}")

    raise typer.Exit(code=1) from error


def get_version() -> str:
    """Return the installed Astra version."""
    try:
        return version("astra")
    except PackageNotFoundError:
        return "0.1.0-dev"


@app.command("version")
def version_info() -> None:
    """Display the installed Astra version."""
    console.print(f"[bold cyan]Astra[/bold cyan] [white]{get_version()}[/white]")


@app.command()
def doctor() -> None:
    """Check Astra's runtime environment and optional tooling."""
    settings = get_settings()
    checks = run_doctor_checks(settings)

    table = Table(title="Astra Environment Check", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Requirement", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")

    for check in checks:
        requirement = "Required" if check.required else "Optional"
        status = "[green]READY[/green]" if check.available else "[red]MISSING[/red]"
        table.add_row(check.component, requirement, status, check.details)

    console.print(table)

    if not doctor_passed(checks):
        console.print("[bold red]One or more required checks failed.[/bold red]")
        raise typer.Exit(code=1)

    console.print("[bold green]All required Astra checks passed.[/bold green]")


@app.command()
def ingest(sample: Path) -> None:
    """Hash and store a sample in Astra quarantine."""
    settings = get_settings()
    metadata = ingest_sample(sample, settings)

    table = Table(title="Sample Ingested", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Sample ID", str(metadata.sample_id))
    table.add_row("Original name", metadata.original_name)
    table.add_row("Size", f"{metadata.size_bytes:,} bytes")
    table.add_row("Quarantine path", str(metadata.source_path))
    table.add_row("MD5", metadata.hashes.md5)
    table.add_row("SHA-1", metadata.hashes.sha1)
    table.add_row("SHA-256", metadata.hashes.sha256)
    table.add_row("SHA-512", metadata.hashes.sha512)

    console.print(table)


@app.command()
def analyze(sample: Path) -> None:
    """Run Astra's unified static-analysis pipeline."""
    try:
        report = AnalysisOrchestrator().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    summary = Table(
        title="Astra Unified Analysis",
        show_header=False,
        box=box.ROUNDED,
    )
    summary.add_column(
        "Field",
        style="bold cyan",
    )
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        report.original_name,
    )
    summary.add_row(
        "Path",
        str(report.sample_path),
    )
    summary.add_row(
        "Size",
        f"{report.size_bytes:,} bytes",
    )
    summary.add_row(
        "Detected family",
        report.file_type.detected_family,
    )
    summary.add_row(
        "MIME type",
        report.file_type.mime_type,
    )
    summary.add_row(
        "SHA-256",
        report.hashes.sha256,
    )
    summary.add_row(
        "Analyzers",
        str(len(report.analyzer_results)),
    )
    summary.add_row(
        "Completed",
        str(report.completed_analyzers),
    )
    summary.add_row(
        "Failed/partial",
        str(report.failed_analyzers),
    )
    summary.add_row(
        "Findings",
        str(len(report.findings)),
    )
    summary.add_row(
        "Duration",
        f"{report.total_duration_ms} ms",
    )

    console.print(summary)

    executions = Table(
        title="Analysis Modules Executed",
        box=box.ROUNDED,
    )
    executions.add_column(
        "Analyzer",
        style="bold cyan",
    )
    executions.add_column(
        "Status",
        justify="center",
    )
    executions.add_column(
        "Findings",
        justify="right",
    )
    executions.add_column(
        "Errors",
        justify="right",
    )
    executions.add_column(
        "Duration",
        justify="right",
    )

    execution_styles = {
        "completed": "green",
        "partial": "yellow",
        "failed": "bold red",
        "skipped": "dim",
    }

    for execution in report.analyzer_executions:
        status = execution.status.lower()
        status_style = execution_styles.get(
            status,
            "white",
        )

        findings_style = "yellow" if execution.finding_count > 0 else "green"

        errors_style = "bold red" if execution.error_count > 0 else "green"

        executions.add_row(
            execution.analyzer,
            (f"[{status_style}]{execution.status.upper()}[/{status_style}]"),
            (f"[{findings_style}]{execution.finding_count}[/{findings_style}]"),
            (f"[{errors_style}]{execution.error_count}[/{errors_style}]"),
            f"{execution.duration_ms} ms",
        )

    console.print(executions)

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }

    if report.findings:
        findings = Table(
            title=(f"Unified Security Findings ({len(report.findings)})"),
            box=box.ROUNDED,
        )
        findings.add_column(
            "Severity",
            justify="center",
        )
        findings.add_column(
            "Category",
            style="cyan",
        )
        findings.add_column("Finding")
        findings.add_column(
            "Confidence",
            justify="right",
        )
        findings.add_column("MITRE")

        for finding in report.findings:
            severity = finding.severity.value
            severity_style = severity_styles.get(
                severity,
                "white",
            )

            findings.add_row(
                (f"[{severity_style}]{severity.upper()}[/{severity_style}]"),
                finding.category,
                finding.title,
                f"{finding.confidence}%",
                (", ".join(finding.attack_techniques) or "-"),
            )

        console.print(findings)
    else:
        console.print("\n[bold green]No suspicious indicators were detected.[/bold green]\n")

    if report.assessment is None:
        console.print("[yellow]Final threat assessment is unavailable.[/yellow]")
        return

    assessment = report.assessment

    if assessment.reasons:
        reasons = Table(
            title="Assessment Evidence",
            box=box.ROUNDED,
        )
        reasons.add_column(
            "Severity",
            justify="center",
        )
        reasons.add_column("Reason")

        for reason in assessment.reasons:
            severity_name, separator, description = reason.partition(":")

            normalized_severity = severity_name.strip().lower()
            reason_style = severity_styles.get(
                normalized_severity,
                "white",
            )

            if separator:
                reasons.add_row(
                    (f"[{reason_style}]{severity_name.strip().upper()}[/{reason_style}]"),
                    description.strip(),
                )
            else:
                reasons.add_row(
                    "-",
                    reason,
                )

        console.print(reasons)

    classification_styles = {
        "likely-benign": "bold green",
        "low-risk": "bold green",
        "suspicious": "bold yellow",
        "medium-risk": "bold yellow",
        "high-risk": "bold red",
        "highly-suspicious": "bold white on red",
        "critical": "bold white on red",
    }

    classification = assessment.classification.value
    classification_style = classification_styles.get(
        classification,
        "bold white",
    )

    if assessment.score >= 70:
        score_style = "bold red"
    elif assessment.score >= 40:
        score_style = "bold yellow"
    else:
        score_style = "bold green"

    if assessment.confidence >= 80:
        confidence_style = "bold green"
    elif assessment.confidence >= 60:
        confidence_style = "yellow"
    else:
        confidence_style = "red"

    final_assessment = Table(
        title="[bold]FINAL THREAT ASSESSMENT[/bold]",
        show_header=False,
        box=box.DOUBLE_EDGE,
        border_style=classification_style,
        title_style=classification_style,
        padding=(0, 2),
    )
    final_assessment.add_column(
        "Field",
        style="bold cyan",
    )
    final_assessment.add_column("Value")

    final_assessment.add_row(
        "Classification",
        (f"[{classification_style}]{classification.upper()}[/{classification_style}]"),
    )
    final_assessment.add_row(
        "Risk score",
        (f"[{score_style}]{assessment.score} / 100[/{score_style}]"),
    )
    final_assessment.add_row(
        "Confidence",
        (f"[{confidence_style}]{assessment.confidence}%[/{confidence_style}]"),
    )
    final_assessment.add_row(
        "MITRE ATT&CK",
        (", ".join(assessment.attack_techniques) or "None"),
    )
    final_assessment.add_row(
        "Total findings",
        str(len(report.findings)),
    )
    final_assessment.add_row(
        "Analyzer status",
        (f"{report.completed_analyzers} completed, {report.failed_analyzers} failed/partial"),
    )

    console.print()
    console.print(final_assessment)


@app.command()
def identify(sample: Path) -> None:
    """Identify the real file type using libmagic."""
    result = identify_file(sample)

    table = Table(title="File Identification", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Filename", result.file_name)
    table.add_row("Extension", result.extension or "(none)")
    table.add_row("Detected family", result.detected_family)
    table.add_row("MIME type", result.mime_type)
    table.add_row("Magic", result.magic_description)
    table.add_row("Executable", "Yes" if result.is_executable else "No")

    if result.extension_matches is None:
        extension_status = "Unknown"
    elif result.extension_matches:
        extension_status = "Match"
    else:
        extension_status = "Mismatch"

    table.add_row("Extension check", extension_status)
    table.add_row("Confidence", f"{result.confidence}%")

    console.print(table)


@app.command()
def strings(
    sample: Path,
    minimum_length: int = 4,
    limit: int = 200,
) -> None:
    """Extract printable ASCII and UTF-16 strings from a sample."""
    analyzer = StringsAnalyzer(
        minimum_length=minimum_length,
        maximum_results=limit,
    )
    result = analyzer.analyze(sample)

    if result.status.value != "completed":
        console.print(
            f"[bold red]String extraction failed:[/bold red] "
            f"{result.errors[0].message if result.errors else 'Unknown error'}"
        )
        raise typer.Exit(code=1)

    data = result.data
    extracted = data["strings"]

    summary = Table(title="String Extraction Summary", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("Minimum length", str(data["minimum_length"]))
    summary.add_row("Total strings", str(data["total_count"]))
    summary.add_row("Displayed", str(len(extracted)))
    summary.add_row("Truncated", "Yes" if data["truncated"] else "No")
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    strings_table = Table(title=f"Extracted Strings ({len(extracted)})")
    strings_table.add_column("Offset", justify="right", style="dim")
    strings_table.add_column("Encoding", justify="center")
    strings_table.add_column("Length", justify="right")
    strings_table.add_column("Value")

    for entry in extracted:
        strings_table.add_row(
            f"0x{int(entry['offset']):08x}",
            str(entry["encoding"]),
            str(entry["length"]),
            str(entry["value"]),
        )

    console.print(strings_table)

    if data["truncated"]:
        console.print(
            f"[dim]Showing the first {len(extracted)} of "
            f"{data['total_count']} extracted strings.[/dim]"
        )


@app.command()
def ioc(sample: Path) -> None:
    """Extract actionable indicators of compromise."""
    result = IOCAnalyzer().analyze(sample)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown IOC analysis error"
        console.print(f"[bold red]IOC analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(title="IOC Extraction", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("Total indicators", str(data["total_indicators"]))
    summary.add_row("Unique indicators", str(data["unique_indicators"]))
    summary.add_row("Categories", str(len(data["summaries"])))
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    if not data["indicators"]:
        console.print("[green]No indicators of compromise detected.[/green]")
        return

    indicators = Table(title=f"Indicators ({len(data['indicators'])})")
    indicators.add_column("Type", style="cyan")
    indicators.add_column("Value")
    indicators.add_column("Offset", justify="right")
    indicators.add_column("Confidence", justify="right")

    for indicator in data["indicators"]:
        offset = indicator["offset"]

        indicators.add_row(
            str(indicator["indicator_type"]),
            str(indicator["value"]),
            f"0x{int(offset):x}" if offset is not None else "-",
            f"{indicator['confidence']}%",
        )

    console.print(indicators)

    if result.findings:
        findings = Table(title="IOC Findings")
        findings.add_column("Severity", justify="center")
        findings.add_column("Finding", style="cyan")
        findings.add_column("Confidence", justify="right")
        findings.add_column("Evidence", justify="right")

        for finding in result.findings:
            findings.add_row(
                finding.severity.value.upper(),
                finding.title,
                f"{finding.confidence}%",
                str(len(finding.evidence)),
            )

        console.print(findings)


@app.command()
def entropy(
    sample: Path,
    block_size: int = 4096,
) -> None:
    """Analyze whole-file and block-level entropy."""
    analyzer = EntropyAnalyzer(block_size=block_size)
    result = analyzer.analyze(sample)
    data = result.data

    summary = Table(title="Entropy Analysis", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("File size", f"{int(data['file_size']):,} bytes")
    summary.add_row("Block size", f"{int(data['block_size']):,} bytes")
    summary.add_row("Overall entropy", f"{float(data['overall_entropy']):.4f} / 8.0000")
    summary.add_row(
        "Maximum region entropy",
        f"{float(data['maximum_region_entropy']):.4f}",
    )
    summary.add_row(
        "High-entropy regions",
        str(data["high_entropy_regions"]),
    )
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    regions = Table(title=f"Entropy Regions ({len(data['regions'])})")
    regions.add_column("Offset", justify="right", style="dim")
    regions.add_column("Size", justify="right")
    regions.add_column("Entropy", justify="right")
    regions.add_column("Assessment")

    for region in data["regions"]:
        entropy_value = float(region["entropy"])
        assessment = "HIGH" if entropy_value >= 7.2 else "Normal"

        regions.add_row(
            f"0x{int(region['offset']):08x}",
            str(region["size"]),
            f"{entropy_value:.4f}",
            assessment,
        )

    console.print(regions)

    if not result.findings:
        console.print("[green]No high-entropy indicators detected.[/green]")
        return

    findings = Table(title=f"Entropy Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding", style="cyan")
    findings.add_column("Confidence", justify="right")
    findings.add_column("Evidence")

    for finding in result.findings:
        evidence = ", ".join(
            f"{item.value} ({item.location})" if item.location else item.value
            for item in finding.evidence
        )

        findings.add_row(
            finding.severity.value.upper(),
            finding.title,
            f"{finding.confidence}%",
            evidence or "(none)",
        )

    console.print(findings)


@app.command()
def signature(sample: Path) -> None:
    """Analyze PE Authenticode signatures and certificates."""
    try:
        result = SignatureAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown signature-analysis error"
        console.print(f"[bold red]Signature analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="Digital Signature Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("Status", str(data["status"]).upper())
    summary.add_row(
        "Signature present",
        "Yes" if data["signature_present"] else "No",
    )
    summary.add_row(
        "Signature valid",
        (
            "Unknown"
            if data["signature_valid"] is None
            else "Yes"
            if data["signature_valid"]
            else "No"
        ),
    )
    summary.add_row(
        "Trust verified",
        (
            "Unknown"
            if data["trust_verified"] is None
            else "Yes"
            if data["trust_verified"]
            else "No"
        ),
    )
    summary.add_row("Signer count", str(data["signer_count"]))
    summary.add_row(
        "Timestamp present",
        "Yes" if data["timestamp_present"] else "No",
    )
    summary.add_row(
        "Digest",
        str(data["digest_algorithm"] or "Unknown"),
    )
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    if data["certificates"]:
        certificates = Table(title=f"Certificates ({len(data['certificates'])})")
        certificates.add_column("Subject")
        certificates.add_column("Issuer")
        certificates.add_column("Valid until")
        certificates.add_column("Expired", justify="center")
        certificates.add_column("Self-signed", justify="center")

        for certificate in data["certificates"]:
            certificates.add_row(
                str(certificate["subject"] or "Unknown"),
                str(certificate["issuer"] or "Unknown"),
                str(certificate["valid_until"] or "Unknown"),
                "Yes" if certificate["is_expired"] else "No",
                "Yes" if certificate["is_self_signed"] else "No",
            )

        console.print(certificates)
    elif data["signature_present"]:
        console.print("[yellow]Signature present, but no certificates were parsed.[/yellow]")
    else:
        console.print("[yellow]The PE file is unsigned.[/yellow]")

    if data["verification_error"]:
        console.print(f"[yellow]Verification note:[/yellow] {data['verification_error']}")

    if result.findings:
        findings = Table(title="Signature Findings")
        findings.add_column("Severity", justify="center")
        findings.add_column("Finding")
        findings.add_column("Confidence", justify="right")

        for finding in result.findings:
            findings.add_row(
                finding.severity.value.upper(),
                finding.title,
                f"{finding.confidence}%",
            )

        console.print(findings)


@app.command()
def sections(sample: Path) -> None:
    """Analyze PE sections, permissions, entropy, and layout."""
    try:
        result = SectionsAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown section-analysis error"
        console.print(f"[bold red]Section analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Section Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Sections",
        str(data["section_count"]),
    )
    summary.add_row(
        "High entropy",
        str(data["high_entropy_sections"]),
    )
    summary.add_row(
        "Executable",
        str(data["executable_sections"]),
    )
    summary.add_row(
        "Writable",
        str(data["writable_sections"]),
    )
    summary.add_row(
        "RWX",
        str(data["rwx_sections"]),
    )
    summary.add_row(
        "W+X",
        str(data["wx_sections"]),
    )
    summary.add_row(
        "Suspicious names",
        str(data["suspicious_name_sections"]),
    )
    summary.add_row(
        "Empty executable",
        str(data["empty_executable_sections"]),
    )
    summary.add_row(
        "Layout anomalies",
        str(data["virtual_raw_anomalies"]),
    )
    summary.add_row(
        "Executable resources",
        str(data["executable_resource_sections"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    section_table = Table(title=f"Sections ({len(data['sections'])})")
    section_table.add_column(
        "Name",
        style="cyan",
    )
    section_table.add_column(
        "RVA",
        justify="right",
    )
    section_table.add_column(
        "Virtual",
        justify="right",
    )
    section_table.add_column(
        "Raw",
        justify="right",
    )
    section_table.add_column(
        "Entropy",
        justify="right",
    )
    section_table.add_column(
        "Permissions",
        justify="center",
    )
    section_table.add_column(
        "Flags",
    )

    for section in data["sections"]:
        permissions = "".join(
            (
                "R" if section["readable"] else "-",
                "W" if section["writable"] else "-",
                "X" if section["executable"] else "-",
            )
        )

        flags: list[str] = []

        if section["is_rwx"]:
            flags.append("RWX")

        if section["is_suspicious_name"]:
            flags.append("Suspicious name")

        if section["has_virtual_raw_anomaly"]:
            flags.append("Layout anomaly")

        if section["is_executable_resource"]:
            flags.append("Executable resource")

        section_table.add_row(
            str(section["name"]),
            f"0x{int(section['virtual_address']):x}",
            str(section["virtual_size"]),
            str(section["raw_size"]),
            f"{float(section['entropy']):.2f}",
            permissions,
            ", ".join(flags) or "-",
        )

    console.print(section_table)

    if not result.findings:
        console.print("[green]No suspicious PE section indicators detected.[/green]")
        return

    findings = Table(title=f"Section Findings ({len(result.findings)})")
    findings.add_column(
        "Severity",
        justify="center",
    )
    findings.add_column(
        "Category",
        style="cyan",
    )
    findings.add_column(
        "Finding",
    )
    findings.add_column(
        "Confidence",
        justify="right",
    )
    findings.add_column(
        "MITRE",
    )

    for finding in result.findings:
        findings.add_row(
            finding.severity.value.upper(),
            finding.category,
            finding.title,
            f"{finding.confidence}%",
            ", ".join(finding.attack_techniques) or "-",
        )

    console.print(findings)


@app.command()
def resources(sample: Path) -> None:
    """Analyze PE resources and embedded payloads."""
    try:
        result = ResourcesAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown resource-analysis error"
        console.print(f"[bold red]Resource analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Resource Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Resources",
        str(data["resource_count"]),
    )
    summary.add_row(
        "Icons",
        str(data["icon_count"]),
    )
    summary.add_row(
        "Manifests",
        str(data["manifest_count"]),
    )
    summary.add_row(
        "Versions",
        str(data["version_count"]),
    )
    summary.add_row(
        "RCDATA",
        str(data["rcdata_count"]),
    )
    summary.add_row(
        "High entropy",
        str(data["high_entropy_resources"]),
    )
    summary.add_row(
        "Embedded executables",
        str(data["embedded_executables"]),
    )
    summary.add_row(
        "Embedded archives",
        str(data["embedded_archives"]),
    )
    summary.add_row(
        "Embedded documents",
        str(data["embedded_documents"]),
    )
    summary.add_row(
        "Total resource bytes",
        f"{int(data['total_resource_bytes']):,}",
    )
    summary.add_row(
        "Largest resource",
        f"{int(data['largest_resource_size']):,} bytes",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    resource_table = Table(title=f"Resources ({len(data['resources'])})")
    resource_table.add_column("Type", style="cyan")
    resource_table.add_column("Name")
    resource_table.add_column("Language")
    resource_table.add_column(
        "RVA",
        justify="right",
    )
    resource_table.add_column(
        "Size",
        justify="right",
    )
    resource_table.add_column(
        "Entropy",
        justify="right",
    )
    resource_table.add_column("Embedded")
    resource_table.add_column("SHA-256")

    for resource in data["resources"]:
        resource_table.add_row(
            str(resource["resource_type"]),
            str(resource["name"] or "-"),
            str(resource["language"] or "-"),
            f"0x{int(resource['rva']):x}",
            f"{int(resource['size']):,}",
            f"{float(resource['entropy']):.2f}",
            str(resource["embedded_file_type"] or "-"),
            str(resource["sha256"])[:16] + "…",
        )

    console.print(resource_table)

    if not result.findings:
        console.print("[green]No suspicious PE resource indicators detected.[/green]")
        return

    findings = Table(title=f"Resource Findings ({len(result.findings)})")
    findings.add_column(
        "Severity",
        justify="center",
    )
    findings.add_column(
        "Category",
        style="cyan",
    )
    findings.add_column("Finding")
    findings.add_column(
        "Confidence",
        justify="right",
    )
    findings.add_column("MITRE")

    for finding in result.findings:
        findings.add_row(
            finding.severity.value.upper(),
            finding.category,
            finding.title,
            f"{finding.confidence}%",
            ", ".join(finding.attack_techniques) or "-",
        )

    console.print(findings)


@app.command()
def pe(sample: Path) -> None:
    """Perform static analysis of a Windows PE file."""
    analyzer = PEAnalyzer()
    result = analyzer.analyze(sample)

    if result.status.value != "completed":
        console.print(
            f"[bold red]PE analysis failed:[/bold red] "
            f"{result.errors[0].message if result.errors else 'Unknown error'}"
        )
        raise typer.Exit(code=1)

    data = result.data
    header = data["header"]

    summary = Table(title="PE Analysis Summary", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Machine", str(header["machine"]))
    summary.add_row("Architecture", f"{header['architecture_bits']}-bit")
    summary.add_row("Subsystem", str(header["subsystem"]))
    summary.add_row("Image base", hex(int(header["image_base"])))
    summary.add_row("Entry point", hex(int(header["entry_point"])))
    summary.add_row("Compile timestamp", str(header["compile_timestamp"]))
    summary.add_row("Sections", str(header["number_of_sections"]))
    summary.add_row("DLL", "Yes" if header["is_dll"] else "No")
    summary.add_row("Driver", "Yes" if header["is_driver"] else "No")
    summary.add_row("Signed", "Yes" if data["signed"] else "No")
    summary.add_row("Resources", "Yes" if data["has_resources"] else "No")
    summary.add_row("TLS callbacks", "Yes" if data["has_tls_callbacks"] else "No")
    summary.add_row("Debug directory", "Yes" if data["has_debug_directory"] else "No")
    summary.add_row("Overlay size", f"{data['overlay_size']:,} bytes")
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    sections = Table(title="PE Sections")
    sections.add_column("Name", style="cyan")
    sections.add_column("Virtual size", justify="right")
    sections.add_column("Raw size", justify="right")
    sections.add_column("Entropy", justify="right")
    sections.add_column("Permissions", justify="center")

    for section in data["sections"]:
        permissions = "".join(
            (
                "R" if section["readable"] else "-",
                "W" if section["writable"] else "-",
                "X" if section["executable"] else "-",
            )
        )

        sections.add_row(
            str(section["name"]),
            str(section["virtual_size"]),
            str(section["raw_size"]),
            f"{float(section['entropy']):.2f}",
            permissions,
        )

    console.print(sections)

    if result.findings:
        findings_table = Table(title=f"Security Findings ({len(result.findings)})")
        findings_table.add_column("Severity", justify="center")
        findings_table.add_column("Finding", style="cyan")
        findings_table.add_column("Confidence", justify="right")
        findings_table.add_column("Evidence")

        severity_styles = {
            "info": "blue",
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold white on red",
        }

        for finding in result.findings:
            severity = finding.severity.value
            style = severity_styles.get(severity, "white")

            evidence = ", ".join(
                f"{item.value} ({item.location})" if item.location else item.value
                for item in finding.evidence
            )

            findings_table.add_row(
                f"[{style}]{severity.upper()}[/{style}]",
                finding.title,
                f"{finding.confidence}%",
                evidence or "(none)",
            )

        console.print(findings_table)
    else:
        console.print(
            Panel(
                "[green]No suspicious PE indicators were detected by the current rules.[/green]",
                title="Security Findings",
                border_style="green",
            )
        )

    imports = Table(title=f"PE Imports ({len(data['imports'])})")
    imports.add_column("Library", style="cyan")
    imports.add_column("Function")

    for imported in data["imports"][:100]:
        imports.add_row(str(imported["library"]), str(imported["function"]))

    console.print(imports)

    if len(data["imports"]) > 100:
        console.print(f"[dim]Showing the first 100 of {len(data['imports'])} imports.[/dim]")


@app.command()
def debug(sample: Path) -> None:
    """Analyze PE debug-directory and PDB metadata."""
    try:
        result = DebugDirectoryAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown debug-directory analysis error"
        )
        console.print(f"[red]Debug-directory analysis failed:[/red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Debug Directory Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Debug directory present",
        "Yes" if data["debug_directory_present"] else "No",
    )
    summary.add_row(
        "Entries",
        str(data["entry_count"]),
    )
    summary.add_row(
        "CodeView entries",
        str(data["codeview_entry_count"]),
    )
    summary.add_row(
        "Reproducible entries",
        str(data["reproducible_entry_count"]),
    )
    summary.add_row(
        "Malformed entries",
        str(data["malformed_entries"]),
    )
    summary.add_row(
        "PDB paths",
        str(data["pdb_path_count"]),
    )
    summary.add_row(
        "Username paths",
        str(data["username_path_count"]),
    )
    summary.add_row(
        "Absolute paths",
        str(data["absolute_path_count"]),
    )
    summary.add_row(
        "Network paths",
        str(data["network_path_count"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    entries = data["entries"]

    if entries:
        table = Table(title=f"Debug Directory Entries ({len(entries)})")
        table.add_column(
            "Index",
            justify="right",
        )
        table.add_column("Type")
        table.add_column("Signature")
        table.add_column("GUID")
        table.add_column(
            "Age",
            justify="right",
        )
        table.add_column("PDB Path")
        table.add_column("Flags")

        for entry in entries:
            flags: list[str] = []

            if entry["malformed"]:
                flags.append("Malformed")

            if entry["path_contains_username"]:
                flags.append("Username")

            if entry["path_is_absolute"]:
                flags.append("Absolute")

            if entry["path_is_network_share"]:
                flags.append("Network")

            table.add_row(
                str(entry["index"]),
                entry["debug_type_name"],
                entry["signature"] or "-",
                entry["pdb_guid"] or "-",
                (str(entry["pdb_age"]) if entry["pdb_age"] is not None else "-"),
                entry["pdb_path"] or "-",
                ", ".join(flags) or "-",
            )

        console.print(table)

    if not result.findings:
        console.print("[green]No suspicious PE debug-directory indicators detected.[/green]")
        return

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    findings = Table(title=f"Debug Directory Findings ({len(result.findings)})")
    findings.add_column(
        "Severity",
        justify="center",
    )
    findings.add_column("Finding")
    findings.add_column(
        "Confidence",
        justify="right",
    )

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def richheader(sample: Path) -> None:
    """Analyze PE Rich Header compiler and toolchain metadata."""
    try:
        result = RichHeaderAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown Rich Header analysis error"
        )
        console.print(f"[red]Rich Header analysis failed:[/red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Rich Header Analysis",
        show_header=False,
    )
    summary.add_column(
        "Field",
        style="cyan",
    )
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Rich header present",
        "Yes" if data["rich_header_present"] else "No",
    )
    summary.add_row(
        "Malformed",
        "Yes" if data["malformed"] else "No",
    )
    summary.add_row(
        "Checksum valid",
        (
            "Yes"
            if data["checksum_valid"] is True
            else ("No" if data["checksum_valid"] is False else "Unknown")
        ),
    )
    summary.add_row(
        "DanS offset",
        (f"0x{data['dans_offset']:x}" if data["dans_offset"] is not None else "-"),
    )
    summary.add_row(
        "Rich offset",
        (f"0x{data['rich_offset']:x}" if data["rich_offset"] is not None else "-"),
    )
    summary.add_row(
        "XOR key",
        (f"0x{data['xor_key']:08x}" if data["xor_key"] is not None else "-"),
    )
    summary.add_row(
        "Entries",
        str(data["entry_count"]),
    )
    summary.add_row(
        "Object count",
        str(data["total_object_count"]),
    )
    summary.add_row(
        "Duplicate entries",
        str(data["duplicate_entries"]),
    )
    summary.add_row(
        "Zero-count entries",
        str(data["zero_count_entries"]),
    )
    summary.add_row(
        "Unknown products",
        str(data["unknown_product_entries"]),
    )
    summary.add_row(
        "Toolchains",
        (", ".join(data["toolchain_families"]) or "Unknown"),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    entries = data["entries"]

    if entries:
        table = Table(title=f"Rich Header Entries ({len(entries)})")
        table.add_column(
            "Product ID",
            justify="right",
        )
        table.add_column(
            "Build",
            justify="right",
        )
        table.add_column(
            "Count",
            justify="right",
        )
        table.add_column("Product")
        table.add_column("Toolchain")

        for entry in entries:
            table.add_row(
                f"0x{entry['product_id']:04x}",
                str(entry["build_number"]),
                str(entry["count"]),
                entry["product_name"] or "Unknown",
                entry["toolchain_family"] or "Unknown",
            )

        console.print(table)

    if not result.findings:
        console.print("[green]No suspicious Rich Header indicators detected.[/green]")
        return

    findings = Table(title=f"Rich Header Findings ({len(result.findings)})")
    findings.add_column(
        "Severity",
        justify="center",
    )
    findings.add_column("Finding")
    findings.add_column(
        "Confidence",
        justify="right",
    )

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def overlay(sample: Path) -> None:
    """Analyze PE overlay and appended-file data."""
    try:
        result = OverlayAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown overlay-analysis error"
        console.print(f"[bold red]Overlay analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Overlay Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Overlay present",
        "Yes" if data["overlay_present"] else "No",
    )
    summary.add_row(
        "Offset",
        (f"0x{data['offset']:x}" if data["offset"] is not None else "-"),
    )
    summary.add_row(
        "Size",
        f"{int(data['size']):,} bytes",
    )
    summary.add_row(
        "Percentage",
        f"{float(data['percentage_of_file']):.2f}%",
    )
    summary.add_row(
        "Entropy",
        (f"{float(data['entropy']):.4f}" if data["entropy"] is not None else "-"),
    )
    summary.add_row(
        "Embedded type",
        str(data["embedded_file_type"] or "-"),
    )
    summary.add_row(
        "Executable",
        "Yes" if data["is_executable"] else "No",
    )
    summary.add_row(
        "Archive",
        "Yes" if data["is_archive"] else "No",
    )
    summary.add_row(
        "Certificate table",
        "Yes" if data["is_certificate_table"] else "No",
    )
    summary.add_row(
        "Installer payload",
        "Yes" if data["is_installer_payload"] else "No",
    )
    summary.add_row(
        "Installer type",
        str(data["installer_type"] or "-"),
    )
    summary.add_row(
        "High entropy",
        "Yes" if data["is_high_entropy"] else "No",
    )
    summary.add_row(
        "Large",
        "Yes" if data["is_large"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if not result.findings:
        console.print("[green]No suspicious PE overlay indicators detected.[/green]")
        return

    findings = Table(title=f"Overlay Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def exports(sample: Path) -> None:
    """Analyze PE export-directory metadata and symbols."""
    try:
        result = ExportsAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown export-analysis error"
        console.print(f"[bold red]Export analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Export Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Export directory present",
        "Yes" if data["export_directory_present"] else "No",
    )
    summary.add_row(
        "Module",
        str(data["module_name"] or "-"),
    )
    summary.add_row(
        "Exports",
        str(data["export_count"]),
    )
    summary.add_row(
        "Named",
        str(data["named_export_count"]),
    )
    summary.add_row(
        "Ordinal only",
        str(data["ordinal_only_count"]),
    )
    summary.add_row(
        "Forwarded",
        str(data["forwarded_export_count"]),
    )
    summary.add_row(
        "Executable",
        str(data["executable_export_count"]),
    )
    summary.add_row(
        "Unmapped",
        str(data["unmapped_export_count"]),
    )
    summary.add_row(
        "Suspicious names",
        str(data["suspicious_name_count"]),
    )
    summary.add_row(
        "Malformed",
        str(data["malformed_export_count"]),
    )
    summary.add_row(
        "Duplicate names",
        str(data["duplicate_name_count"]),
    )
    summary.add_row(
        "Duplicate ordinals",
        str(data["duplicate_ordinal_count"]),
    )
    summary.add_row(
        "Large export table",
        "Yes" if data["unusually_large_export_table"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    entries = data["exports"]

    if entries:
        table = Table(title=f"PE Exports ({len(entries)})")
        table.add_column(
            "Ordinal",
            justify="right",
        )
        table.add_column("Name")
        table.add_column("RVA")
        table.add_column("Section")
        table.add_column("Forwarder")
        table.add_column("Flags")

        for entry in entries[:200]:
            flags: list[str] = []

            if entry["is_executable"]:
                flags.append("Executable")

            if entry["is_forwarded"]:
                flags.append("Forwarded")

            if entry["suspicious_name"]:
                flags.append("Suspicious name")

            if entry["malformed"]:
                flags.append("Malformed")

            table.add_row(
                str(entry["ordinal"]),
                str(entry["name"] or "-"),
                f"0x{int(entry['rva']):x}",
                str(entry["section_name"] or "-"),
                str(entry["forwarder"] or "-"),
                ", ".join(flags) or "-",
            )

        console.print(table)

        if len(entries) > 200:
            console.print(f"[dim]Showing the first 200 of {len(entries)} exports.[/dim]")

    if not result.findings:
        console.print("[green]No suspicious PE export indicators detected.[/green]")
        return

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    findings = Table(title=f"Export Findings ({len(result.findings)})")
    findings.add_column(
        "Severity",
        justify="center",
    )
    findings.add_column("Finding")
    findings.add_column(
        "Confidence",
        justify="right",
    )

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def manifest(sample: Path) -> None:
    """Analyze Windows PE application manifest metadata."""
    try:
        result = ManifestAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown manifest-analysis error"
        console.print(f"[bold red]Manifest analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Application Manifest Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Manifest present",
        "Yes" if data["manifest_present"] else "No",
    )
    summary.add_row(
        "Manifest count",
        str(data["manifest_count"]),
    )
    summary.add_row(
        "Execution level",
        str(data["requested_execution_level"] or "-"),
    )
    summary.add_row(
        "UIAccess",
        ("Yes" if data["ui_access"] is True else "No" if data["ui_access"] is False else "-"),
    )
    summary.add_row(
        "Requires administrator",
        "Yes" if data["requires_administrator"] else "No",
    )
    summary.add_row(
        "Highest available",
        "Yes" if data["highest_available"] else "No",
    )
    summary.add_row(
        "As invoker",
        "Yes" if data["as_invoker"] else "No",
    )
    summary.add_row(
        "Auto elevate",
        "Yes" if data["auto_elevate"] else "No",
    )
    summary.add_row(
        "DPI aware",
        ("Yes" if data["dpi_aware"] is True else "No" if data["dpi_aware"] is False else "-"),
    )
    summary.add_row(
        "Long path aware",
        (
            "Yes"
            if data["long_path_aware"] is True
            else "No"
            if data["long_path_aware"] is False
            else "-"
        ),
    )
    summary.add_row(
        "Supported OS entries",
        str(data["supported_os_count"]),
    )
    summary.add_row(
        "Dependencies",
        str(data["dependency_count"]),
    )
    summary.add_row(
        "Requested privileges",
        "Yes" if data["requested_privileges_present"] else "No",
    )
    summary.add_row(
        "Malformed",
        "Yes" if data["malformed"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["supported_os_ids"]:
        os_table = Table(title="Supported Windows OS Identifiers")
        os_table.add_column("Identifier", style="cyan")

        for os_id in data["supported_os_ids"]:
            os_table.add_row(str(os_id))

        console.print(os_table)

    if data["dependencies"]:
        dependencies = Table(title=f"Manifest Dependencies ({len(data['dependencies'])})")
        dependencies.add_column("Name", style="cyan")
        dependencies.add_column("Version")
        dependencies.add_column("Architecture")
        dependencies.add_column("Public Key Token")
        dependencies.add_column("Type")

        for dependency in data["dependencies"]:
            dependencies.add_row(
                str(dependency["name"]),
                str(dependency["version"] or "-"),
                str(dependency["processor_architecture"] or "-"),
                str(dependency["public_key_token"] or "-"),
                str(dependency["dependency_type"] or "-"),
            )

        console.print(dependencies)

    if not result.findings:
        console.print("[green]No suspicious PE manifest indicators detected.[/green]")
        return

    findings = Table(title=f"Manifest Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def tls(sample: Path) -> None:
    """Analyze PE TLS callbacks and execution-flow metadata."""
    try:
        result = TLSAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown TLS-analysis error"
        console.print(f"[bold red]TLS analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE TLS Callback Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "TLS present",
        "Yes" if data["tls_present"] else "No",
    )
    summary.add_row(
        "Callbacks",
        str(data["callback_count"]),
    )
    summary.add_row(
        "Mapped callbacks",
        str(data["mapped_callbacks"]),
    )
    summary.add_row(
        "Executable callbacks",
        str(data["executable_callbacks"]),
    )
    summary.add_row(
        "Writable callbacks",
        str(data["writable_callbacks"]),
    )
    summary.add_row(
        "Outside image",
        str(data["outside_image_callbacks"]),
    )
    summary.add_row(
        "Suspicious callbacks",
        str(data["suspicious_callbacks"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    callbacks = data["callbacks"]

    if callbacks:
        table = Table(title=f"TLS Callbacks ({len(callbacks)})")
        table.add_column("Index", justify="right")
        table.add_column("Virtual address")
        table.add_column("RVA")
        table.add_column("File offset")
        table.add_column("Section")
        table.add_column("Flags")

        for callback in callbacks:
            flags: list[str] = []

            if callback["is_mapped"]:
                flags.append("Mapped")

            if callback["is_executable"]:
                flags.append("Executable")

            if callback["is_writable"]:
                flags.append("Writable")

            if callback["is_outside_image"]:
                flags.append("Outside image")

            table.add_row(
                str(callback["index"]),
                f"0x{int(callback['virtual_address']):x}",
                f"0x{int(callback['relative_virtual_address']):x}",
                (
                    f"0x{int(callback['file_offset']):x}"
                    if callback["file_offset"] is not None
                    else "-"
                ),
                str(callback["section_name"] or "-"),
                ", ".join(flags) or "-",
            )

        console.print(table)

    if not result.findings:
        console.print("[green]No suspicious PE TLS indicators detected.[/green]")
        return

    findings = Table(title=f"TLS Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def fingerprints(sample: Path) -> None:
    """Generate PE import fingerprints and ImpHash."""
    try:
        result = FingerprintsAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown fingerprint-analysis error"
        )
        console.print(f"[bold red]Fingerprint analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Fingerprint Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Fingerprint available",
        "Yes" if data["fingerprint_available"] else "No",
    )
    summary.add_row(
        "ImpHash",
        str(data["imphash"] or "-"),
    )
    summary.add_row(
        "Libraries",
        str(data["import_library_count"]),
    )
    summary.add_row(
        "Imports",
        str(data["import_count"]),
    )
    summary.add_row(
        "Named imports",
        str(data["named_import_count"]),
    )
    summary.add_row(
        "Ordinal imports",
        str(data["ordinal_import_count"]),
    )
    summary.add_row(
        "Malformed imports",
        str(data["malformed_import_count"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["libraries"]:
        table = Table(title=f"Fingerprint Libraries ({len(data['libraries'])})")
        table.add_column("Library", style="cyan")
        table.add_column("Imports", justify="right")
        table.add_column("Named", justify="right")
        table.add_column("Ordinal", justify="right")

        for library in data["libraries"]:
            table.add_row(
                str(library["name"]),
                str(library["import_count"]),
                str(library["named_import_count"]),
                str(library["ordinal_import_count"]),
            )

        console.print(table)

    if data["fingerprint_source"]:
        source = str(data["fingerprint_source"])
        preview_length = 240
        preview = source if len(source) <= preview_length else f"{source[:preview_length]}..."

        console.print("[bold]Normalized fingerprint source preview:[/bold]")
        console.print(preview)

    console.print("[green]Fingerprint generation completed.[/green]")


@app.command()
def versioninfo(sample: Path) -> None:
    """Analyze PE version-information metadata."""
    try:
        result = VersionInfoAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown version-info analysis error"
        )
        console.print(f"[bold red]Version-info analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Version Information Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Version info present",
        "Yes" if data["version_info_present"] else "No",
    )
    summary.add_row(
        "Company",
        str(data["company_name"] or "-"),
    )
    summary.add_row(
        "Description",
        str(data["file_description"] or "-"),
    )
    summary.add_row(
        "File version",
        str(data["file_version"] or "-"),
    )
    summary.add_row(
        "Original filename",
        str(data["original_filename"] or "-"),
    )
    summary.add_row(
        "Product",
        str(data["product_name"] or "-"),
    )
    summary.add_row(
        "Product version",
        str(data["product_version"] or "-"),
    )
    summary.add_row(
        "Filename matches",
        (
            "Yes"
            if data["original_filename_matches"] is True
            else ("No" if data["original_filename_matches"] is False else "Unknown")
        ),
    )
    summary.add_row(
        "Suspicious company",
        "Yes" if data["suspicious_company_name"] else "No",
    )
    summary.add_row(
        "Suspicious product",
        "Yes" if data["suspicious_product_name"] else "No",
    )
    summary.add_row(
        "Missing identity fields",
        "Yes" if data["missing_identity_fields"] else "No",
    )
    summary.add_row(
        "Version strings",
        str(data["string_count"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if not result.findings:
        console.print("[green]No suspicious PE version-information indicators detected.[/green]")
        return

    findings = Table(title=f"Version Information Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def embedded(sample: Path) -> None:
    """Discover and recursively analyze embedded payloads."""
    try:
        orchestrator = AnalysisOrchestrator()

        analyzer = EmbeddedAnalyzer(
            child_analyzer=lambda path: orchestrator.analyze(
                path,
                include_embedded=False,
            )
        )

        result = analyzer.analyze(sample)

    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown embedded-payload analysis error"
        )

        console.print(f"[bold red]Embedded analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="Recursive Embedded Payload Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Embedded payloads",
        "Yes" if data["embedded_payloads_present"] else "No",
    )
    summary.add_row(
        "Payloads",
        str(data["payload_count"]),
    )
    summary.add_row(
        "Analyzed",
        str(data["analyzed_payload_count"]),
    )
    summary.add_row(
        "Executables",
        str(data["executable_payload_count"]),
    )
    summary.add_row(
        "Archives",
        str(data["archive_payload_count"]),
    )
    summary.add_row(
        "Documents",
        str(data["document_payload_count"]),
    )
    summary.add_row(
        "Scripts",
        str(data["script_payload_count"]),
    )
    summary.add_row(
        "Duplicates",
        str(data["duplicate_payload_count"]),
    )
    summary.add_row(
        "Skipped",
        str(data["skipped_payload_count"]),
    )
    summary.add_row(
        "Maximum depth",
        str(data["maximum_depth_reached"]),
    )
    summary.add_row(
        "Extracted bytes",
        f"{data['total_extracted_bytes']:,}",
    )
    summary.add_row(
        "Recursion limit",
        "Yes" if data["recursion_limit_reached"] else "No",
    )
    summary.add_row(
        "Payload limit",
        "Yes" if data["payload_limit_reached"] else "No",
    )
    summary.add_row(
        "Byte limit",
        "Yes" if data["byte_limit_reached"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["payloads"]:
        payload_table = Table(title=f"Embedded Payloads ({len(data['payloads'])})")

        payload_table.add_column(
            "Index",
            justify="right",
        )
        payload_table.add_column(
            "Parent",
            justify="right",
        )
        payload_table.add_column(
            "Depth",
            justify="right",
        )
        payload_table.add_column("Source")
        payload_table.add_column("Family")
        payload_table.add_column(
            "Size",
            justify="right",
        )
        payload_table.add_column(
            "Entropy",
            justify="right",
        )
        payload_table.add_column("SHA-256")
        payload_table.add_column("Flags")
        payload_table.add_column("Assessment")

        for payload in data["payloads"]:
            parent_index = payload["parent_index"]

            flags: list[str] = []

            if payload["duplicate"]:
                flags.append("duplicate")

            if payload["truncated"]:
                flags.append("truncated")

            if payload["identity"]["is_executable"]:
                flags.append("executable")

            analysis = payload["analysis"]

            assessment = "-"

            if analysis["analyzed"]:
                classification = analysis["classification"] or "unknown"

                risk_score = analysis["risk_score"]

                assessment = classification

                if risk_score is not None:
                    assessment = f"{classification} ({risk_score}/100)"

            entropy = payload["entropy"]

            payload_table.add_row(
                str(payload["index"]),
                ("-" if parent_index is None else str(parent_index)),
                str(payload["depth"]),
                str(payload["location"]["source"]),
                str(payload["identity"]["detected_family"]),
                f"{payload['location']['size']:,}",
                ("-" if entropy is None else f"{entropy:.2f}"),
                str(payload["identity"]["sha256"])[:16] + "...",
                ", ".join(flags) or "-",
                assessment,
            )

        console.print(payload_table)

    if result.findings:
        findings_table = Table(title=f"Embedded Findings ({len(result.findings)})")

        findings_table.add_column(
            "Severity",
            justify="center",
        )
        findings_table.add_column("Finding")
        findings_table.add_column(
            "Confidence",
            justify="right",
        )

        severity_styles = {
            "info": "blue",
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold white on red",
        }

        for finding in result.findings:
            severity = finding.severity.value
            style = severity_styles.get(
                severity,
                "white",
            )

            findings_table.add_row(
                f"[{style}]{severity.upper()}[/{style}]",
                finding.title,
                f"{finding.confidence}%",
            )

        console.print(findings_table)

    else:
        console.print("[green]No suspicious embedded payload indicators detected.[/green]")


@app.command()
def relocations(sample: Path) -> None:
    """Analyze PE base-relocation metadata."""
    try:
        result = RelocationsAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown relocation-analysis error"
        console.print(f"[bold red]Relocation analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Relocation Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Relocation directory",
        "Yes" if data["relocation_directory_present"] else "No",
    )
    summary.add_row(
        "Blocks",
        str(data["block_count"]),
    )
    summary.add_row(
        "Relocations",
        str(data["relocation_count"]),
    )
    summary.add_row(
        "Mapped",
        str(data["mapped_relocation_count"]),
    )
    summary.add_row(
        "Executable",
        str(data["executable_relocation_count"]),
    )
    summary.add_row(
        "Writable",
        str(data["writable_relocation_count"]),
    )
    summary.add_row(
        "Malformed",
        str(data["malformed_relocation_count"]),
    )
    summary.add_row(
        "Unknown types",
        str(data["unknown_type_count"]),
    )
    summary.add_row(
        "Types",
        ", ".join(data["relocation_types"]) or "-",
    )
    summary.add_row(
        "Large table",
        "Yes" if data["unusually_large_relocation_table"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["blocks"]:
        table = Table(title=f"Relocation Blocks ({len(data['blocks'])})")
        table.add_column("Index", justify="right")
        table.add_column("Page RVA")
        table.add_column("Block size")
        table.add_column("Entries")
        table.add_column("Malformed")

        for block in data["blocks"][:100]:
            table.add_row(
                str(block["index"]),
                f"0x{int(block['page_rva']):x}",
                str(block["block_size"]),
                str(block["entry_count"]),
                str(block["malformed_entry_count"]),
            )

        console.print(table)

        if len(data["blocks"]) > 100:
            console.print(
                f"[dim]Showing the first 100 of {len(data['blocks'])} relocation blocks.[/dim]"
            )

    if not result.findings:
        console.print("[green]No suspicious PE relocation indicators detected.[/green]")
        return

    findings = Table(title=f"Relocation Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def dotnet(sample: Path) -> None:
    """Analyze .NET CLR and managed metadata."""
    try:
        result = DotNetAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown .NET analysis error"
        console.print(f"[bold red].NET analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title=".NET CLR Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        ".NET present",
        "Yes" if data["dotnet_present"] else "No",
    )
    summary.add_row(
        "CLR header",
        "Yes" if data["clr_header_present"] else "No",
    )
    summary.add_row(
        "Metadata",
        "Yes" if data["metadata_present"] else "No",
    )
    summary.add_row(
        "Runtime",
        str(data["runtime_version"] or "-"),
    )
    summary.add_row(
        "CLR header size",
        str(data["clr_header_size"]),
    )
    summary.add_row(
        "CLR flags",
        ", ".join(data["clr_flag_names"]) or "-",
    )
    summary.add_row(
        "IL only",
        "Yes" if data["il_only"] else "No",
    )
    summary.add_row(
        "32-bit required",
        "Yes" if data["thirty_two_bit_required"] else "No",
    )
    summary.add_row(
        "32-bit preferred",
        "Yes" if data["thirty_two_bit_preferred"] else "No",
    )
    summary.add_row(
        "Strong-name signed",
        "Yes" if data["strong_name_signed"] else "No",
    )
    summary.add_row(
        "Native entry point",
        "Yes" if data["native_entry_point"] else "No",
    )
    summary.add_row(
        "Mixed mode",
        "Yes" if data["mixed_mode"] else "No",
    )
    summary.add_row(
        "Entry-point token",
        (
            f"0x{int(data['entry_point_token']):08x}"
            if data["entry_point_token"] is not None
            else "-"
        ),
    )
    summary.add_row(
        "Entry-point RVA",
        (f"0x{int(data['entry_point_rva']):x}" if data["entry_point_rva"] is not None else "-"),
    )
    summary.add_row(
        "Metadata version",
        str(data["metadata_version"] or "-"),
    )
    summary.add_row(
        "Assembly",
        str(data["assembly_name"] or "-"),
    )
    summary.add_row(
        "Assembly version",
        str(data["assembly_version"] or "-"),
    )
    summary.add_row(
        "Module",
        str(data["module_name"] or "-"),
    )
    summary.add_row(
        "Streams",
        str(data["stream_count"]),
    )
    summary.add_row(
        "Assembly references",
        str(data["assembly_reference_count"]),
    )
    summary.add_row(
        "Type definitions",
        str(data["type_definition_count"]),
    )
    summary.add_row(
        "Method definitions",
        str(data["method_definition_count"]),
    )
    summary.add_row(
        "Member references",
        str(data["member_reference_count"]),
    )
    summary.add_row(
        "P/Invoke methods",
        str(data["pinvoke_method_count"]),
    )
    summary.add_row(
        "Malformed metadata",
        "Yes" if data["malformed_metadata"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["streams"]:
        streams = Table(title=f".NET Metadata Streams ({len(data['streams'])})")
        streams.add_column("Name", style="cyan")
        streams.add_column("Offset")
        streams.add_column("Size", justify="right")

        for stream in data["streams"]:
            streams.add_row(
                str(stream["name"]),
                f"0x{int(stream['offset']):x}",
                str(stream["size"]),
            )

        console.print(streams)

    if data["assembly_references"]:
        references = Table(title=f"Assembly References ({len(data['assembly_references'])})")
        references.add_column("Assembly", style="cyan")
        references.add_column("Version")
        references.add_column("Culture")

        for reference in data["assembly_references"]:
            references.add_row(
                str(reference["name"]),
                str(reference["version"] or "-"),
                str(reference["culture"] or "-"),
            )

        console.print(references)

    if not result.findings:
        console.print("[green]No suspicious .NET CLR indicators detected.[/green]")
        return

    findings = Table(title=f".NET Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def elf(sample: Path) -> None:
    """Perform foundational static analysis of an ELF file."""
    try:
        result = ELFAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown ELF analysis error"

        console.print(f"[bold red]ELF analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data
    header = data["header"]
    dynamic = data["dynamic"]
    security = data["security"]

    summary = Table(
        title="ELF Static Analysis",
        show_header=False,
    )

    summary.add_column(
        "Field",
        style="cyan",
    )
    summary.add_column(
        "Value",
    )

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Architecture",
        f"{header['machine']} ({header['architecture_bits']}-bit)",
    )
    summary.add_row(
        "Endian",
        str(header["endianness"]),
    )
    summary.add_row(
        "Type",
        str(header["elf_type"]),
    )
    summary.add_row(
        "OS ABI",
        str(header["os_abi"]),
    )
    summary.add_row(
        "Entry point",
        f"0x{header['entry_point']:x}",
    )
    summary.add_row(
        "Sections",
        str(data["section_count"]),
    )
    summary.add_row(
        "Segments",
        str(data["segment_count"]),
    )
    summary.add_row(
        "Interpreter",
        dynamic["interpreter"] or "-",
    )
    summary.add_row(
        "Dynamic libraries",
        str(len(dynamic["needed_libraries"])),
    )
    summary.add_row(
        "PIE",
        "Yes" if security["pie"] else "No",
    )
    summary.add_row(
        "NX",
        "Yes" if security["nx_enabled"] else "No",
    )
    summary.add_row(
        "RELRO",
        ("Full" if security["full_relro"] else ("Partial" if security["relro"] else "No")),
    )
    summary.add_row(
        "Stack canary",
        "Yes" if security["has_stack_canary"] else "No",
    )
    summary.add_row(
        "Stripped",
        "Yes" if security["stripped"] else "No",
    )
    summary.add_row(
        "RPATH",
        dynamic["rpath"] or "-",
    )
    summary.add_row(
        "RUNPATH",
        dynamic["runpath"] or "-",
    )
    summary.add_row(
        "Malformed",
        "Yes" if data["malformed"] else "No",
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if dynamic["needed_libraries"]:
        libraries = Table(title=(f"ELF Required Libraries ({len(dynamic['needed_libraries'])})"))

        libraries.add_column("Library")

        for library in dynamic["needed_libraries"]:
            libraries.add_row(str(library))

        console.print(libraries)

    if result.findings:
        findings = Table(title=(f"ELF Findings ({len(result.findings)})"))

        findings.add_column("Severity")
        findings.add_column("Finding")
        findings.add_column("Confidence")

        for finding in result.findings:
            findings.add_row(
                finding.severity.value.upper(),
                finding.title,
                f"{finding.confidence}%",
            )

        console.print(findings)
    else:
        console.print("[green]No suspicious ELF indicators detected.[/green]")


@app.command()
def elfsymbols(sample: Path) -> None:
    """Analyze ELF symbols, imports, exports, and capabilities."""
    try:
        result = ELFSymbolsAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown ELF symbol analysis error"

        console.print(f"[bold red]ELF symbol analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="ELF Symbol Analysis",
        show_header=False,
    )

    summary.add_column(
        "Field",
        style="cyan",
    )
    summary.add_column(
        "Value",
    )

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Symbol tables",
        ("Yes" if data["symbol_tables_present"] else "No"),
    )
    summary.add_row(
        "Symbols",
        str(data["symbol_count"]),
    )
    summary.add_row(
        "Dynamic symbols",
        str(data["dynamic_symbol_count"]),
    )
    summary.add_row(
        "Static symbols",
        str(data["static_symbol_count"]),
    )
    summary.add_row(
        "Imports",
        str(data["import_count"]),
    )
    summary.add_row(
        "Exports",
        str(data["export_count"]),
    )
    summary.add_row(
        "Weak symbols",
        str(data["weak_symbol_count"]),
    )
    summary.add_row(
        "Suspicious symbols",
        str(data["suspicious_symbol_count"]),
    )
    summary.add_row(
        "Duplicate symbols",
        str(data["duplicate_symbol_count"]),
    )
    summary.add_row(
        "Malformed symbols",
        str(data["malformed_symbol_count"]),
    )
    summary.add_row(
        "Stripped",
        ("Yes" if data["stripped"] else "No"),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    suspicious_symbols = [symbol for symbol in data["symbols"] if symbol["suspicious"]]

    if suspicious_symbols:
        symbol_table = Table(title=(f"Capability-Bearing ELF Imports ({len(suspicious_symbols)})"))

        symbol_table.add_column("Symbol")
        symbol_table.add_column("Category")
        symbol_table.add_column("Binding")
        symbol_table.add_column("Type")

        for symbol in suspicious_symbols:
            symbol_table.add_row(
                str(symbol["name"]),
                str(symbol["suspicious_category"] or "-"),
                str(symbol["binding"]),
                str(symbol["symbol_type"]),
            )

        console.print(symbol_table)

    if result.findings:
        findings_table = Table(title=(f"ELF Symbol Findings ({len(result.findings)})"))

        findings_table.add_column("Severity")
        findings_table.add_column("Category")
        findings_table.add_column("Finding")
        findings_table.add_column(
            "Confidence",
            justify="right",
        )

        for finding in result.findings:
            findings_table.add_row(
                finding.severity.value.upper(),
                finding.category,
                finding.title,
                f"{finding.confidence}%",
            )

        console.print(findings_table)

    else:
        console.print("[green]No suspicious ELF symbol capabilities detected.[/green]")


@app.command()
def importdirectories(sample: Path) -> None:
    """Analyze PE delay-import and bound-import directories."""
    try:
        result = ImportDirectoriesAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown import-directory analysis error"
        )
        console.print(f"[bold red]Import-directory analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Delay/Bound Import Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Delay-import directory",
        "Yes" if data["delay_import_directory_present"] else "No",
    )
    summary.add_row(
        "Bound-import directory",
        "Yes" if data["bound_import_directory_present"] else "No",
    )
    summary.add_row(
        "Delay libraries",
        str(data["delay_library_count"]),
    )
    summary.add_row(
        "Delay imports",
        str(data["delay_import_count"]),
    )
    summary.add_row(
        "Suspicious delay imports",
        str(data["suspicious_delay_import_count"]),
    )
    summary.add_row(
        "Bound libraries",
        str(data["bound_library_count"]),
    )
    summary.add_row(
        "Malformed bound imports",
        str(data["malformed_bound_import_count"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if data["delay_libraries"]:
        delay_table = Table(title="Delay Imports")
        delay_table.add_column("Library", style="cyan")
        delay_table.add_column("Name")
        delay_table.add_column("Ordinal")
        delay_table.add_column("Address")
        delay_table.add_column("Suspicious")

        for library in data["delay_libraries"]:
            for imported in library["imports"]:
                delay_table.add_row(
                    str(library["library"]),
                    str(imported["name"] or "-"),
                    (str(imported["ordinal"]) if imported["ordinal"] is not None else "-"),
                    f"0x{int(imported['address']):x}",
                    "Yes" if imported["suspicious"] else "No",
                )

        console.print(delay_table)

    if data["bound_imports"]:
        bound_table = Table(title="Bound Imports")
        bound_table.add_column("Library", style="cyan")
        bound_table.add_column("Timestamp")
        bound_table.add_column("Forwarders")
        bound_table.add_column("Malformed")

        for bound in data["bound_imports"]:
            bound_table.add_row(
                str(bound["library"]),
                str(bound["timestamp"]),
                str(bound["forwarder_count"]),
                "Yes" if bound["malformed"] else "No",
            )

        console.print(bound_table)

    if not result.findings:
        console.print("[green]No suspicious PE delay/bound import indicators detected.[/green]")
        return

    findings = Table(title=f"Import Directory Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(
            severity,
            "white",
        )

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def loadconfig(sample: Path) -> None:
    """Analyze PE load configuration and binary mitigations."""
    try:
        result = LoadConfigAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = (
            result.errors[0].message if result.errors else "Unknown load-config analysis error"
        )
        console.print(f"[bold red]Load-config analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(
        title="PE Load Configuration Analysis",
        show_header=False,
    )
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row(
        "Sample",
        str(sample.expanduser().resolve()),
    )
    summary.add_row(
        "Load config present",
        "Yes" if data["load_config_present"] else "No",
    )
    summary.add_row(
        "Size",
        f"{int(data['size']):,} bytes",
    )
    summary.add_row(
        "Security cookie",
        "Yes" if data["security_cookie_present"] else "No",
    )
    summary.add_row(
        "Control Flow Guard",
        "Yes" if data["control_flow_guard_enabled"] else "No",
    )
    summary.add_row(
        "Guard flags",
        ", ".join(data["guard_flag_names"]) or "-",
    )
    summary.add_row(
        "Guard functions",
        str(data["guard_cf_function_count"]),
    )
    summary.add_row(
        "SafeSEH applicable",
        "Yes" if data["safe_seh_applicable"] else "No",
    )
    summary.add_row(
        "SafeSEH present",
        "Yes" if data["safe_seh_present"] else "No",
    )
    summary.add_row(
        "SEH handlers",
        str(data["seh_handler_count"]),
    )
    summary.add_row(
        "Code integrity",
        "Yes" if data["code_integrity_present"] else "No",
    )
    summary.add_row(
        "Malformed",
        "Yes" if data["malformed"] else "No",
    )
    summary.add_row(
        "Invalid pointers",
        str(data["invalid_pointer_count"]),
    )
    summary.add_row(
        "Duration",
        f"{result.duration_ms} ms",
    )

    console.print(summary)

    if not result.findings:
        console.print("[green]No suspicious PE load-configuration indicators detected.[/green]")
        return

    findings = Table(title=f"Load Configuration Findings ({len(result.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for finding in result.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.title,
            f"{finding.confidence}%",
        )

    console.print(findings)


@app.command()
def metadata(sample: Path) -> None:
    """Extract normalized PE metadata."""
    try:
        result = MetadataAnalyzer().analyze(sample)
    except (FileNotFoundError, ValueError) as error:
        _handle_path_error(error)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown metadata-analysis error"
        console.print(f"[bold red]Metadata analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(title="Metadata Analysis", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("Entries", str(data["entry_count"]))
    summary.add_row(
        "Version info",
        "Yes" if data["has_version_info"] else "No",
    )
    summary.add_row(
        "Compile timestamp",
        str(data["compile_timestamp"] or "Unknown"),
    )
    summary.add_row(
        "Compile datetime",
        str(data["compile_datetime"] or "Unknown"),
    )
    summary.add_row(
        "Suspicious timestamp",
        "Yes" if data["suspicious_timestamp"] else "No",
    )
    summary.add_row(
        "Future timestamp",
        "Yes" if data["future_timestamp"] else "No",
    )
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    fields = Table(title="Normalized Metadata")
    fields.add_column("Field", style="cyan")
    fields.add_column("Value")

    normalized_fields = (
        ("Company", data["company_name"]),
        ("Product", data["product_name"]),
        ("Description", data["file_description"]),
        ("Original filename", data["original_filename"]),
        ("Internal name", data["internal_name"]),
        ("Product version", data["product_version"]),
        ("File version", data["file_version"]),
        ("Copyright", data["legal_copyright"]),
        ("Language", data["language"]),
    )

    for label, value in normalized_fields:
        if value:
            fields.add_row(label, str(value))

    if fields.row_count:
        console.print(fields)
    else:
        console.print("[yellow]No normalized version metadata found.[/yellow]")

    if result.findings:
        findings = Table(title="Metadata Findings")
        findings.add_column("Severity", justify="center")
        findings.add_column("Finding")
        findings.add_column("Confidence", justify="right")

        for finding in result.findings:
            findings.add_row(
                finding.severity.value.upper(),
                finding.title,
                f"{finding.confidence}%",
            )

        console.print(findings)


@app.command()
def imports(sample: Path) -> None:
    """Profile suspicious Windows API imports."""
    analyzer = ImportAnalyzer()
    result = analyzer.analyze(sample)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown import-analysis error"
        console.print(f"[bold red]Import analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(title="Import Behavior Analysis", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row("Total imports", str(data["total_imports"]))
    summary.add_row("Suspicious imports", str(data["suspicious_imports"]))
    summary.add_row("Behavior groups", str(len(data["behaviors"])))
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    if not result.findings:
        console.print("[green]No suspicious imported APIs detected.[/green]")
        return

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    indicators = Table(title=f"Suspicious Imports ({len(result.findings)})")
    indicators.add_column("Severity", justify="center")
    indicators.add_column("Library", style="cyan")
    indicators.add_column("Function")
    indicators.add_column("Behavior")
    indicators.add_column("Confidence", justify="right")
    indicators.add_column("MITRE")

    for finding in result.findings:
        evidence = finding.evidence[0]
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        indicators.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            evidence.location or "(unknown)",
            evidence.value,
            finding.category,
            f"{finding.confidence}%",
            ", ".join(finding.attack_techniques) or "-",
        )

    console.print(indicators)

    behaviors = Table(title="Behavior Summary")
    behaviors.add_column("Behavior", style="cyan")
    behaviors.add_column("Count", justify="right")
    behaviors.add_column("Maximum severity", justify="center")

    for behavior in data["behaviors"]:
        severity = str(behavior["maximum_severity"])
        style = severity_styles.get(severity, "white")

        behaviors.add_row(
            str(behavior["category"]),
            str(behavior["count"]),
            f"[{style}]{severity.upper()}[/{style}]",
        )

    console.print(behaviors)


@app.command()
def packer(sample: Path) -> None:
    """Detect PE packing and executable protection indicators."""
    analyzer = PackerAnalyzer()
    result = analyzer.analyze(sample)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown packer-analysis error"
        console.print(f"[bold red]Packer analysis failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    data = result.data

    summary = Table(title="Packer Detection", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample.expanduser().resolve()))
    summary.add_row(
        "Likely packed",
        "[bold red]Yes[/bold red]" if data["is_likely_packed"] else "[green]No[/green]",
    )
    summary.add_row("Confidence", f"{data['confidence']}%")
    summary.add_row("Detected packer", str(data["detected_packer"] or "Unknown"))
    summary.add_row("High-entropy sections", str(data["high_entropy_sections"]))
    summary.add_row(
        "RWX sections",
        str(data["executable_writable_sections"]),
    )
    summary.add_row(
        "Suspicious section names",
        str(data["suspicious_section_names"]),
    )
    summary.add_row("Import count", str(data["import_count"]))
    summary.add_row("Overlay size", f"{int(data['overlay_size']):,} bytes")
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    if not data["indicators"]:
        console.print("[green]No packing indicators detected.[/green]")
        return

    indicators = Table(title=f"Packer Indicators ({len(data['indicators'])})")
    indicators.add_column("Severity", justify="center")
    indicators.add_column("Type", style="cyan")
    indicators.add_column("Value")
    indicators.add_column("Location")
    indicators.add_column("Confidence", justify="right")

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    for indicator in data["indicators"]:
        severity = str(indicator["severity"])
        style = severity_styles.get(severity, "white")

        indicators.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            str(indicator["indicator_type"]),
            str(indicator["value"]),
            str(indicator["location"] or "-"),
            f"{indicator['confidence']}%",
        )

    console.print(indicators)

    if data["candidates"]:
        candidates = Table(title="Packer Candidates")
        candidates.add_column("Packer", style="cyan")
        candidates.add_column("Confidence", justify="right")
        candidates.add_column("Indicators", justify="right")

        for candidate in data["candidates"]:
            candidates.add_row(
                str(candidate["name"]),
                f"{candidate['confidence']}%",
                str(len(candidate["indicators"])),
            )

        console.print(candidates)


@app.command()
def yara(sample: Path) -> None:
    """Scan a sample using Astra YARA rules."""
    analyzer = YaraAnalyzer(Path("rules/yara"))
    result = analyzer.analyze(sample)

    if result.status is not AnalysisStatus.COMPLETED:
        message = result.errors[0].message if result.errors else "Unknown YARA error"
        console.print(f"[bold red]YARA scan failed:[/bold red] {message}")
        raise typer.Exit(code=1)

    summary = Table(title="YARA Analysis", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", str(sample))
    summary.add_row("Rules root", str(result.data["rules_root"]))
    summary.add_row("Matches", str(result.data["match_count"]))
    summary.add_row("Duration", f"{result.duration_ms} ms")

    console.print(summary)

    if not result.findings:
        console.print("[green]No YARA matches found.[/green]")
        return

    findings = Table(title="YARA Findings")
    findings.add_column("Severity", style="bold")
    findings.add_column("Rule", style="cyan")
    findings.add_column("Category")
    findings.add_column("Confidence", justify="right")

    for finding in result.findings:
        findings.add_row(
            finding.severity.value.upper(),
            finding.title.removeprefix("YARA rule matched: "),
            finding.category,
            f"{finding.confidence}%",
        )

    console.print(findings)

    for finding in result.findings:
        if not finding.evidence:
            continue

        evidence = Table(title=f"Evidence — {finding.title}")
        evidence.add_column("Identifier", style="cyan")
        evidence.add_column("Offset")
        evidence.add_column("Matched data")

        for item in finding.evidence:
            evidence.add_row(
                str(item.metadata.get("identifier", "")),
                item.location or "",
                item.value,
            )

        console.print(evidence)


@app.command()
def banner() -> None:
    """Display the Astra project banner."""
    console.print(
        Panel.fit(
            "[bold cyan]ASTRA[/bold cyan]\n"
            "[white]Static and Dynamic Malware Analysis Platform[/white]\n\n"
            "[dim]Evidence-driven. Modular. Explainable.[/dim]",
            border_style="cyan",
            title="Malware Analysis",
        )
    )


if __name__ == "__main__":
    app()
