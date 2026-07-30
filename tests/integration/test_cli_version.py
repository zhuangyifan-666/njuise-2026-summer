from typer.testing import CliRunner

from repoproof.cli import app


def test_version_prints_semver_without_ansi() -> None:
    result = CliRunner().invoke(app, ["version"], color=False)

    assert result.exit_code == 0
    assert result.stdout == "repoproof 1.0.0\n"
    assert "\x1b[" not in result.stdout
