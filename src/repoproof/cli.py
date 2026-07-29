import getpass
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Never

import keyring
import typer

from repoproof import __version__
from repoproof.app import AuditRequest, default_dependencies, run_audit
from repoproof.credentials import CredentialStore, KeyringBackend, normalize_host
from repoproof.errors import RuntimeFailure, UsageFailure
from repoproof.profile.loader import load_profile
from repoproof.reporting.console import render_console
from repoproof.reporting.html_reporter import render_html
from repoproof.reporting.json_reporter import render_json
from repoproof.reporting.output import atomic_write_text

app = typer.Typer(no_args_is_help=True, help="Audit repository release readiness.")
profile_app = typer.Typer(help="Inspect and validate audit profiles.")
app.add_typer(profile_app, name="profile")
auth_app = typer.Typer(help="Manage optional GitHub credentials in the OS keyring.")
app.add_typer(auth_app, name="auth")


class ReportFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"


class _TokenReadStatus(StrEnum):
    OK = "ok"
    NOT_INTERACTIVE = "not_interactive"
    UNAVAILABLE = "unavailable"


def _keyring_backend() -> KeyringBackend | None:
    try:
        return keyring.get_keyring()
    except Exception:
        return None


def _credential_store() -> CredentialStore:
    backend = _keyring_backend()
    if backend is None:
        raise UsageFailure(
            "System keyring is unavailable.",
            "Enable an OS keyring backend; plaintext fallback is disabled.",
        )
    return CredentialStore(backend)


def _hidden_token_status() -> tuple[_TokenReadStatus, str | None]:
    if not sys.stdin.isatty():
        return (_TokenReadStatus.NOT_INTERACTIVE, None)
    try:
        return (_TokenReadStatus.OK, getpass.getpass("GitHub Token: "))
    except Exception:
        return (_TokenReadStatus.UNAVAILABLE, None)


def _read_hidden_token() -> str:
    status, token = _hidden_token_status()
    if status is _TokenReadStatus.NOT_INTERACTIVE:
        raise UsageFailure(
            "auth login requires interactive input.", "Run auth login in an interactive terminal."
        )
    if status is not _TokenReadStatus.OK or token is None:
        raise UsageFailure(
            "Hidden token input is unavailable.", "Run auth login in an interactive terminal."
        )
    return token


def _usage_exit(error: UsageFailure) -> Never:
    typer.echo(f"usage: {error.message}\nfix: {error.remediation}", err=True)
    raise typer.Exit(2) from None


@app.callback()
def main() -> None:
    """Audit repository release readiness."""


@app.command()
def version() -> None:
    """Print the installed RepoProof version."""
    typer.echo(f"repoproof {__version__}")


@app.command()
def audit(
    repository: Path = typer.Argument(Path(".")),
    profile: str = typer.Option("ai4se-b", "--profile"),
    formats: Annotated[list[ReportFormat] | None, typer.Option("--format")] = None,
    output: Path | None = typer.Option(None, "--output"),
    offline: bool = typer.Option(False, "--offline"),
    no_color: bool = typer.Option(False, "--no-color"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Audit a repository and render console, JSON, or HTML reports."""
    selected = formats or [ReportFormat.CONSOLE]
    non_console = [item for item in selected if item is not ReportFormat.CONSOLE]
    try:
        if len(non_console) > 1 and (output is None or not output.is_dir()):
            raise UsageFailure(
                "Multiple file formats require an output directory.",
                "Pass --output with an existing directory.",
            )

        report = run_audit(AuditRequest(repository, profile, offline), default_dependencies())
        for item in selected:
            if item is ReportFormat.CONSOLE:
                typer.echo(
                    render_console(
                        report,
                        color=not no_color and sys.stdout.isatty(),
                        verbose=verbose,
                    ),
                    nl=False,
                )
                continue
            target = output / f"report.{item.value}" if output and output.is_dir() else output
            rendered = render_json(report) if item is ReportFormat.JSON else render_html(report)
            if target is None:
                typer.echo(rendered, nl=False)
            else:
                atomic_write_text(target, rendered)
        raise typer.Exit(int(report.exit_code))
    except UsageFailure as exc:
        typer.echo(f"usage: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    except RuntimeFailure as exc:
        typer.echo(f"runtime: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(3) from None
    except typer.Exit:
        raise
    except Exception:
        typer.echo(
            "runtime: audit failed safely\nfix: rerun with --verbose or report the failure",
            err=True,
        )
        raise typer.Exit(3) from None


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


@auth_app.command("login")
def auth_login(host: str = typer.Option("github.com", "--host")) -> None:
    """Store a GitHub token with the system keyring's hidden terminal prompt."""
    try:
        _credential_store().login(host, _read_hidden_token())
        normalized = normalize_host(host)
    except UsageFailure as exc:
        _usage_exit(exc)
    typer.echo(f"credential stored for {normalized}")


@auth_app.command("status")
def auth_status(host: str = typer.Option("github.com", "--host")) -> None:
    """Report whether the keyring contains a credential, without reading it to output."""
    try:
        store = _credential_store()
        configured = "yes" if store.configured(host) else "no"
        backend = store.backend_name()
    except UsageFailure as exc:
        _usage_exit(exc)
    typer.echo(f"configured: {configured}\nbackend: {backend}")


@auth_app.command("logout")
def auth_logout(host: str = typer.Option("github.com", "--host")) -> None:
    """Clear a GitHub credential from the system keyring if one is configured."""
    try:
        _credential_store().logout(host)
        normalized = normalize_host(host)
    except UsageFailure as exc:
        _usage_exit(exc)
    typer.echo(f"credential cleared for {normalized}")
