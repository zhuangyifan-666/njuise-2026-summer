import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Never

import httpx
import pytest
from typer.testing import CliRunner

from repoproof.cli import app

ROOT = Path(__file__).parents[2]


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-07-29T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-07-29T00:00:00+00:00",
        },
    )


def _initialize_acceptance_history(repository: Path) -> None:
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "RepoProof Acceptance")
    _git(repository, "config", "user.email", "acceptance@example.invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "fixture: initial evidence")
    (repository / "history-main.md").write_text("main evidence\n", encoding="utf-8")
    _git(repository, "add", "history-main.md")
    _git(repository, "commit", "-m", "fixture: add main evidence")
    _git(repository, "switch", "-c", "acceptance-evidence")
    (repository / "history-feature.md").write_text("feature evidence\n", encoding="utf-8")
    _git(repository, "add", "history-feature.md")
    _git(repository, "commit", "-m", "fixture: add feature evidence")
    _git(repository, "switch", "main")
    (repository / "history-before-merge.md").write_text("merge evidence\n", encoding="utf-8")
    _git(repository, "add", "history-before-merge.md")
    _git(repository, "commit", "-m", "fixture: prepare merge evidence")
    _git(repository, "merge", "--no-ff", "acceptance-evidence", "-m", "fixture: merge evidence")


def _network_access_forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("offline audit attempted network access")


def test_compliant_fixture_is_auditable_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "compliant-repo"
    shutil.copytree(ROOT / "examples/compliant-repo", repository)
    _initialize_acceptance_history(repository)
    monkeypatch.setattr(httpx, "Client", _network_access_forbidden)
    monkeypatch.setattr(socket, "create_connection", _network_access_forbidden)

    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(repository),
            "--profile",
            "ai4se-b",
            "--offline",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["report_schema"] == 1
    assert {(item["rule_id"], item["status"]) for item in payload["findings"]} == {
        ("ci.github", "PASS"),
        ("ci.gitlab-unit-test", "PASS"),
        ("distribution.windows-release", "PASS"),
        ("docs.required", "PASS"),
        ("git.minimum-history", "PASS"),
        ("git.process-evidence", "PASS"),
        ("plan.commit-evidence", "PASS"),
        ("readme.sections", "PASS"),
        ("security.secrets", "PASS"),
        ("test.entry", "PASS"),
    }


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
