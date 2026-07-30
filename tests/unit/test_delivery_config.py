from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).parents[2]


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
    assert _step_index(steps, uses="actions/checkout@v4") < _step_index(
        steps, uses="actions/setup-python@v5"
    )


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
