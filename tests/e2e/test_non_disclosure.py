from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app

CANARY = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"


def test_canary_is_absent_from_console_json_html_and_errors(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "leak.txt").write_text(f"token={CANARY}\n", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(repository),
            "--offline",
            "--format",
            "console",
            "--format",
            "json",
            "--format",
            "html",
            "--output",
            str(reports),
            "--verbose",
            "--no-color",
        ],
    )

    observed = result.stdout + result.stderr
    observed += (reports / "report.json").read_text(encoding="utf-8")
    observed += (reports / "report.html").read_text(encoding="utf-8")
    assert CANARY not in observed
    assert "<redacted" in observed
    assert "fingerprint" in observed
