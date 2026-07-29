from typer.testing import CliRunner

from repoproof.cli import app

TOKEN = "github_pat_" + "canary_0123456789abcdef"


class FakeStore:
    def __init__(self) -> None:
        self.token: str | None = None

    def login(self, host: str, token: str) -> None:
        self.token = token

    def configured(self, host: str) -> bool:
        return self.token is not None

    def logout(self, host: str) -> None:
        self.token = None

    def backend_name(self) -> str:
        return "FakeKeyring"


def test_auth_lifecycle_never_prints_token(monkeypatch) -> None:
    """Catches auth output that leaks the interactive token during lifecycle operations."""
    store = FakeStore()
    monkeypatch.setattr("repoproof.cli._credential_store", lambda: store)
    monkeypatch.setattr("repoproof.cli._read_hidden_token", lambda: TOKEN)
    runner = CliRunner()

    login = runner.invoke(app, ["auth", "login"])
    configured = runner.invoke(app, ["auth", "status"])
    logout = runner.invoke(app, ["auth", "logout"])
    cleared = runner.invoke(app, ["auth", "status"])
    combined = "".join(
        result.stdout + result.stderr for result in (login, configured, logout, cleared)
    )

    assert [result.exit_code for result in (login, configured, logout, cleared)] == [0, 0, 0, 0]
    assert TOKEN not in combined
    assert "configured: yes" in configured.stdout
    assert "configured: no" in cleared.stdout


def test_auth_login_rejects_unexpected_token_without_disclosure() -> None:
    """Catches Click's default usage diagnostic echoing an unexpected token-like argument."""
    token = "github_pat_" + "parse_canary_0123456789abcdef"
    result = CliRunner().invoke(app, ["auth", "login", token])
    pending = [result.exception]
    seen: set[int] = set()

    while pending:
        error = pending.pop()
        if error is None or id(error) in seen:
            continue
        seen.add(id(error))
        assert token not in repr(error)
        pending.extend((error.__cause__, error.__context__))

    assert result.exit_code == 2
    assert token not in result.stdout
    assert token not in result.stderr
    assert "interactive" in result.stderr.casefold()


def test_auth_status_prints_normalized_host(monkeypatch) -> None:
    """Catches status output that omits or prints a non-canonical configured host."""
    monkeypatch.setattr("repoproof.cli._credential_store", lambda: FakeStore())

    result = CliRunner().invoke(app, ["auth", "status", "--host", "GitHub.COM."])

    assert result.exit_code == 0
    assert result.stdout == "host: github.com\nconfigured: no\nbackend: FakeKeyring\n"
