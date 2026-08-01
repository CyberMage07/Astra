"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from analyzers.filetype import identify_file
from analyzers.pe import PEAnalyzer
from packages.config import get_settings
from packages.core import doctor_passed, ingest_sample, run_doctor_checks

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

    imports = Table(title=f"PE Imports ({len(data['imports'])})")
    imports.add_column("Library", style="cyan")
    imports.add_column("Function")

    for imported in data["imports"][:100]:
        imports.add_row(str(imported["library"]), str(imported["function"]))

    console.print(imports)

    if len(data["imports"]) > 100:
        console.print(f"[dim]Showing the first 100 of {len(data['imports'])} imports.[/dim]")


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
