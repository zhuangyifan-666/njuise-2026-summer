import typer

from repoproof import __version__

app = typer.Typer(no_args_is_help=True, help="Audit repository release readiness.")


@app.callback()
def main() -> None:
    """Audit repository release readiness."""


@app.command()
def version() -> None:
    """Print the installed RepoProof version."""
    typer.echo(f"repoproof {__version__}")
