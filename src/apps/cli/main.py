"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
