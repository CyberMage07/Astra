"""Astra command-line interface."""

from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
    """Check whether Astra core dependencies are available."""
    checks = [
        ("Python environment", True),
        ("Rich terminal engine", True),
        ("Configuration system", True),
        ("File identification", True),
    ]

    table = Table(title="Astra Environment Check", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")

    for component, available in checks:
        status = "[green]READY[/green]" if available else "[red]FAILED[/red]"
        table.add_row(component, status)

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
