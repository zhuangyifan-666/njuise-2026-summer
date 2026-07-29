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
