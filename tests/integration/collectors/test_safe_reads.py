import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

import repoproof.collectors.ci as ci_module
import repoproof.collectors.distribution as distribution_module
import repoproof.collectors.markdown as markdown_module
from repoproof.collectors.base import AuditContext
from repoproof.collectors.ci import CICollector
from repoproof.collectors.distribution import DistributionCollector
from repoproof.collectors.markdown import MarkdownCollector
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile
from repoproof.security import open_regular_file, resolve_under_root


def _profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate(
        {
            "schema": 1,
            "name": "safe-read-test",
            "description": "Safe collector read test.",
            "rules": [rule],
        }
    )


def _replace_with_directory_link(target: Path, outside: Path) -> None:
    for child in target.iterdir():
        child.unlink()
    target.rmdir()
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(target), str(outside)],
            capture_output=True,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("junction creation unavailable")
    else:
        try:
            target.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlink creation unavailable")


def _remove_directory_link(path: Path) -> None:
    if os.path.isjunction(path):
        path.rmdir()
    elif path.is_symlink():
        path.unlink()


def _race_checked_path(
    module: ModuleType,
    root: Path,
    relative: str,
    outside: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    target_directory = (root / relative).parent
    original_resolve = getattr(module, "resolve_under_root", resolve_under_root)
    replaced = False

    def replace_once() -> None:
        nonlocal replaced
        if not replaced:
            _replace_with_directory_link(target_directory, outside)
            replaced = True

    def racing_resolve(given_root: Path, candidate: str) -> Path:
        resolved = original_resolve(given_root, candidate)
        if Path(candidate).as_posix() == relative:
            replace_once()
        return resolved

    def racing_open(given_root: Path, candidate: str):
        if Path(candidate).as_posix() == relative:
            replace_once()
        return open_regular_file(given_root, candidate)

    monkeypatch.setattr(module, "resolve_under_root", racing_resolve, raising=False)
    monkeypatch.setattr(module, "open_regular_file", racing_open, raising=False)
    return target_directory


def _assert_limited_without_outside_marker(
    collect: Callable[[], Evidence], target_directory: Path
) -> None:
    try:
        evidence = collect()
    finally:
        _remove_directory_link(target_directory)
    assert evidence.state is EvidenceState.LIMITED
    assert "outside-marker" not in repr(evidence.facts)


def test_markdown_replacement_link_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "README.md").write_text("# Internal\n", encoding="utf-8")
    outside = tmp_path / "outside-markdown"
    outside.mkdir()
    (outside / "README.md").write_text("# Outside-marker\n", encoding="utf-8")
    profile = _profile(
        {
            "id": "docs.readme",
            "type": "markdown_sections",
            "severity": "error",
            "params": {"path": "docs/README.md", "headings": ["Internal"]},
            "remediation": "Add the heading.",
        }
    )
    target = _race_checked_path(
        markdown_module, tmp_path, "docs/README.md", outside, monkeypatch
    )

    _assert_limited_without_outside_marker(
        lambda: MarkdownCollector().collect(AuditContext(tmp_path, offline=True), profile)[0],
        target,
    )


def test_ci_replacement_link_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "ci"
    config.mkdir()
    (config / "pipeline.yml").write_text("unit-test:\n  script: [pytest]\n", encoding="utf-8")
    outside = tmp_path / "outside-ci"
    outside.mkdir()
    (outside / "pipeline.yml").write_text(
        "outside-marker:\n  script: [exfiltrate]\n", encoding="utf-8"
    )
    profile = _profile(
        {
            "id": "ci.gitlab.unit",
            "type": "ci_job_exists",
            "severity": "error",
            "params": {"ci": "gitlab", "path": "ci/pipeline.yml", "job": "unit-test"},
            "remediation": "Add the job.",
        }
    )
    target = _race_checked_path(ci_module, tmp_path, "ci/pipeline.yml", outside, monkeypatch)

    _assert_limited_without_outside_marker(
        lambda: CICollector().collect(AuditContext(tmp_path, offline=True), profile)[0],
        target,
    )


def test_distribution_replacement_link_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "repoproof.spec").write_text("a = Analysis([])\n", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text(
        "on:\n  push:\n    tags: ['v*']\n", encoding="utf-8"
    )
    outside = tmp_path / "outside-workflows"
    outside.mkdir()
    (outside / "release.yml").write_text(
        "outside-marker: true\non:\n  push:\n    tags: ['v*']\n", encoding="utf-8"
    )
    profile = _profile(
        {
            "id": "distribution.ready",
            "type": "distribution_ready",
            "severity": "error",
            "params": {"allowed": ["python"]},
            "remediation": "Add packaging.",
        }
    )
    target = _race_checked_path(
        distribution_module,
        tmp_path,
        ".github/workflows/release.yml",
        outside,
        monkeypatch,
    )

    _assert_limited_without_outside_marker(
        lambda: DistributionCollector().collect(
            AuditContext(tmp_path, offline=True), profile
        )[0],
        target,
    )
