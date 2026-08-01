"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from packages.config import get_settings
from packages.core import doctor_passed, run_doctor_checks

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
