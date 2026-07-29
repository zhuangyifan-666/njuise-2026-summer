from pathlib import Path

import typer

from repoproof import __version__
from repoproof.errors import UsageFailure
from repoproof.profile.loader import load_profile

app = typer.Typer(no_args_is_help=True, help="Audit repository release readiness.")
profile_app = typer.Typer(help="Inspect and validate audit profiles.")
app.add_typer(profile_app, name="profile")


@app.callback()
def main() -> None:
    """Audit repository release readiness."""


@app.command()
def version() -> None:
    """Print the installed RepoProof version."""
    typer.echo(f"repoproof {__version__}")


@profile_app.command("list")
def profile_list() -> None:
    typer.echo("ai4se-b")


@profile_app.command("validate")
def profile_validate(profile_path: Path) -> None:
    try:
        profile = load_profile(str(profile_path))
    except UsageFailure as exc:
        typer.echo(f"profile: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"valid profile: {profile.name} (schema {profile.schema})")
