"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from analyzers.entropy import EntropyAnalyzer
from analyzers.filetype import identify_file
from analyzers.packer import PackerAnalyzer
from analyzers.pe import PEAnalyzer
from analyzers.signatures import ImportAnalyzer
from analyzers.strings import StringsAnalyzer
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
    report = AnalysisOrchestrator().analyze(sample)

    summary = Table(title="Astra Unified Analysis", show_header=False)
    summary.add_column("Field", style="cyan")
    summary.add_column("Value")

    summary.add_row("Sample", report.original_name)
    summary.add_row("Path", str(report.sample_path))
    summary.add_row("Size", f"{report.size_bytes:,} bytes")
    summary.add_row("Detected family", report.file_type.detected_family)
    summary.add_row("MIME type", report.file_type.mime_type)
    summary.add_row("SHA-256", report.hashes.sha256)
    summary.add_row("Analyzers", str(len(report.analyzer_results)))
    summary.add_row("Completed", str(report.completed_analyzers))
    summary.add_row("Failed/partial", str(report.failed_analyzers))
    summary.add_row("Findings", str(len(report.findings)))
    summary.add_row("Duration", f"{report.total_duration_ms} ms")

    console.print(summary)
    if report.assessment is not None:
        assessment = report.assessment

        classification_styles = {
            "likely-benign": "green",
            "low-risk": "green",
            "suspicious": "yellow",
            "high-risk": "red",
            "highly-suspicious": "bold white on red",
        }

        classification = assessment.classification.value
        style = classification_styles.get(classification, "white")

        verdict = Table(title="Threat Assessment", show_header=False)
        verdict.add_column("Field", style="cyan")
        verdict.add_column("Value")

        verdict.add_row(
            "Classification",
            f"[{style}]{classification.upper()}[/{style}]",
        )
        verdict.add_row("Risk score", f"{assessment.score} / 100")
        verdict.add_row("Confidence", f"{assessment.confidence}%")
        verdict.add_row(
            "MITRE ATT&CK",
            ", ".join(assessment.attack_techniques) or "None",
        )

        console.print(verdict)

        if assessment.reasons:
            reasons = Table(title="Assessment Reasons")
            reasons.add_column("Reason")

            for reason in assessment.reasons:
                reasons.add_row(reason)

            console.print(reasons)

    executions = Table(title="Analyzer Execution")
    executions.add_column("Analyzer", style="cyan")
    executions.add_column("Status", justify="center")
    executions.add_column("Findings", justify="right")
    executions.add_column("Errors", justify="right")
    executions.add_column("Duration", justify="right")

    for execution in report.analyzer_executions:
        executions.add_row(
            execution.analyzer,
            execution.status.upper(),
            str(execution.finding_count),
            str(execution.error_count),
            f"{execution.duration_ms} ms",
        )

    console.print(executions)

    if not report.findings:
        console.print("[green]No suspicious indicators detected.[/green]")
        return

    severity_styles = {
        "info": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold white on red",
    }

    findings = Table(title=f"Unified Findings ({len(report.findings)})")
    findings.add_column("Severity", justify="center")
    findings.add_column("Category", style="cyan")
    findings.add_column("Finding")
    findings.add_column("Confidence", justify="right")
    findings.add_column("MITRE")

    for finding in report.findings:
        severity = finding.severity.value
        style = severity_styles.get(severity, "white")

        findings.add_row(
            f"[{style}]{severity.upper()}[/{style}]",
            finding.category,
            finding.title,
            f"{finding.confidence}%",
            ", ".join(finding.attack_techniques) or "-",
        )

    console.print(findings)


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
