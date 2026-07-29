import json
from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app

ROOT = Path(__file__).parents[2]


def test_compliant_fixture_is_auditable_without_network() -> None:
    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(ROOT / "examples/compliant-repo"),
            "--profile",
            "ai4se-b",
            "--offline",
            "--format",
            "json",
        ],
    )

    assert result.exit_code in (0, 1)
    assert json.loads(result.stdout)["report_schema"] == 1
    assert "network" not in result.stderr.casefold()


def test_noncompliant_fixture_has_failures() -> None:
    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(ROOT / "examples/noncompliant-repo"),
            "--offline",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert any(item["status"] == "FAIL" for item in json.loads(result.stdout)["findings"])


def test_repeated_audits_are_semantically_identical() -> None:
    repository = ROOT / "examples/noncompliant-repo"
    runner = CliRunner()
    first = json.loads(
        runner.invoke(app, ["audit", str(repository), "--offline", "--format", "json"]).stdout
    )
    second = json.loads(
        runner.invoke(app, ["audit", str(repository), "--offline", "--format", "json"]).stdout
    )

    first.pop("generated_at")
    second.pop("generated_at")
    first.pop("timings_ms")
    second.pop("timings_ms")
    assert first == second
