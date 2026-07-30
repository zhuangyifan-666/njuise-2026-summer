import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from importlib.metadata import version as installed_version
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from typer.testing import CliRunner

from repoproof.cli import app

ROOT = Path(__file__).parents[2]


def test_installed_cli_reports_release_version() -> None:
    result = CliRunner().invoke(app, ["version"], color=False)

    assert result.exit_code == 0
    assert installed_version("repoproof") == "1.0.0"
    assert result.stdout == "repoproof 1.0.0\n"


def _load_yaml(path: Path) -> Mapping[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    if True in loaded:
        loaded["on"] = loaded.pop(True)
    return cast(Mapping[str, Any], loaded)


def _workflow(name: str) -> Mapping[str, Any]:
    return _load_yaml(ROOT / ".github" / "workflows" / name)


def _steps(job: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    steps = job.get("steps")
    assert isinstance(steps, list)
    assert all(isinstance(step, dict) for step in steps)
    return cast(Sequence[Mapping[str, Any]], steps)


def _step_index(steps: Sequence[Mapping[str, Any]], *, uses: str) -> int:
    return next(index for index, step in enumerate(steps) if step.get("uses") == uses)


def _step_names(steps: Sequence[Mapping[str, Any]]) -> list[str]:
    return [cast(str, step["name"]) for step in steps]


def _full_history_checkout_index(steps: Sequence[Mapping[str, Any]]) -> int:
    index = _step_index(steps, uses="actions/checkout@v4")
    assert steps[index].get("with") == {"fetch-depth": 0}
    return index


def test_gitlab_defines_the_required_unit_test_job() -> None:
    config = _load_yaml(ROOT / ".gitlab-ci.yml")

    assert config["unit-test"] == {
        "image": "python:3.12",
        "script": ['python -m pip install -e ".[dev]"', "python -m pytest"],
    }


def test_ci_runs_the_supported_python_versions_with_read_only_permissions() -> None:
    config = _workflow("ci.yml")
    jobs = cast(Mapping[str, Any], config["jobs"])
    verify = cast(Mapping[str, Any], jobs["verify"])
    matrix = cast(Mapping[str, Any], verify["strategy"])["matrix"]
    steps = _steps(verify)

    assert config["permissions"] == {"contents": "read"}
    assert config["on"] == {"push": None, "pull_request": None}
    assert verify["runs-on"] == "ubuntu-latest"
    assert cast(Mapping[str, Any], matrix)["python-version"] == ["3.12", "3.13"]
    assert verify["strategy"]["fail-fast"] is False
    assert _step_names(steps) == [
        "Check out repository",
        "Set up Python",
        "Install dependencies",
        "Lint",
        "Type-check",
        "Test",
    ]
    checkout_index = _full_history_checkout_index(steps)
    assert checkout_index < _step_index(steps, uses="actions/setup-python@v5")


def test_release_is_tag_only_and_validates_artifacts_before_publishing() -> None:
    config = _workflow("release.yml")
    jobs = cast(Mapping[str, Any], config["jobs"])
    build = cast(Mapping[str, Any], jobs["build"])
    steps = _steps(build)
    publish_index = _step_index(steps, uses="softprops/action-gh-release@v2")
    artifact_step = steps[_step_index(steps, uses="actions/upload-artifact@v4")]
    release_step = steps[publish_index]

    assert config["on"] == {"push": {"tags": ["v*"]}}
    assert config["permissions"] == {"contents": "write"}
    assert build["runs-on"] == "windows-latest"
    _full_history_checkout_index(steps)
    assert _step_names(steps) == [
        "Check out repository",
        "Set up Python",
        "Install dependencies",
        "Lint",
        "Type-check",
        "Test",
        "Build one-file executable",
        "Name, smoke-test, and checksum the release asset",
        "Upload release artifact",
        "Publish GitHub Release",
    ]
    assert artifact_step["with"]["path"] == (
        "dist/${{ env.ASSET_NAME }}\n"
        "dist/${{ env.ASSET_NAME }}.sha256\n"
    )
    assert release_step["with"]["files"] == (
        "dist/${{ env.ASSET_NAME }}\n"
        "dist/${{ env.ASSET_NAME }}.sha256\n"
    )
    release_body = ROOT / "RELEASE.md"
    assert release_step["with"]["body_path"] == release_body.name
    document = release_body.read_text(encoding="utf-8")
    assert all(
        section in document
        for section in (
            "Windows 10/11 x64",
            "Get-FileHash",
            "SmartScreen",
            "offline",
            "keyring",
            "source",
        )
    )


@pytest.mark.parametrize(
    ("reported_version", "audit_exit"),
    (("9.9.9", "0"), ("1.0.0", "1")),
)
def test_release_smoke_gate_rejects_wrong_version_or_failing_fixture(
    tmp_path: Path, reported_version: str, audit_exit: str
) -> None:
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh is None:
        pytest.skip("PowerShell is required to execute the release smoke gate")
    jobs = cast(Mapping[str, Any], _workflow("release.yml")["jobs"])
    build = cast(Mapping[str, Any], jobs["build"])
    smoke = next(
        step
        for step in _steps(build)
        if step.get("name") == "Name, smoke-test, and checksum the release asset"
    )
    source = cast(str, smoke["run"])
    executable = tmp_path / "fake.ps1"
    executable.write_text(
        "param([string]$Command)\n"
        'if ($Command -eq "version") { Write-Output "repoproof $env:FAKE_VERSION"; exit 0 }\n'
        'if ($Command -eq "audit") { exit ([int]$env:FAKE_AUDIT_EXIT) }\n'
        "exit 4\n",
        encoding="utf-8",
    )
    smoke_lines: list[str] = []
    for line in source.splitlines():
        if "./scripts/write_checksum.ps1" in line:
            break
        if "Move-Item" in line or "GITHUB_ENV" in line:
            continue
        smoke_lines.append(line)
    smoke_script = "\n".join(smoke_lines)
    smoke_script = smoke_script.replace("${{ github.ref_name }}", "v1.0.0")
    smoke_script = smoke_script.replace('& "dist/$name"', '& "$PSScriptRoot/fake.ps1"')
    script = tmp_path / "smoke.ps1"
    script.write_text(smoke_script, encoding="utf-8")
    environment = os.environ.copy()
    environment["FAKE_VERSION"] = reported_version
    environment["FAKE_AUDIT_EXIT"] = audit_exit

    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
