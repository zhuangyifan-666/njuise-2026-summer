from pathlib import Path

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.ci import CICollector
from repoproof.domain import EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile
from repoproof.profile.models import Profile


def test_gitlab_jobs_exclude_reserved_keys(tmp_path: Path) -> None:
    """Catches GitLab global configuration being reported as runnable jobs."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "stages: [test]\nunit-test:\n  script: [python -m pytest]\n", encoding="utf-8"
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].facts["jobs"] == ("unit-test",)
    assert "stages" not in evidence[0].facts["jobs"]


def test_gitlab_spec_header_document_is_excluded_from_jobs(tmp_path: Path) -> None:
    """Catches GitLab's optional preamble document being parsed as a CI job."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "spec:\n  inputs:\n    environment:\n      default: test\n---\n"
        "stages: [test]\nunit-test:\n  script: [python -m pytest]\n",
        encoding="utf-8",
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].facts["jobs"] == ("unit-test",)


def test_legacy_gitlab_pages_job_is_reported(tmp_path: Path) -> None:
    """Catches valid legacy GitLab Pages jobs being discarded as global configuration."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "pages:\n  script: [build-docs]\n", encoding="utf-8"
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].facts["jobs"] == ("pages",)


def test_unsupported_gitlab_multi_document_stream_is_limited(tmp_path: Path) -> None:
    """Catches unsupported YAML document streams reported as empty available CI evidence."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "metadata:\n  owner: release\n---\nunit-test:\n  script: [python -m pytest]\n",
        encoding="utf-8",
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].state is EvidenceState.LIMITED
    assert evidence[0].facts == {"reason": "unsafe_or_invalid_yaml"}


def test_unsafe_yaml_tag_is_limited_without_executing_input(tmp_path: Path) -> None:
    """Catches unsafe YAML construction or treating a rejected tag as valid CI evidence."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "x: !!python/object/apply:os.system ['whoami']\n", encoding="utf-8"
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].state is EvidenceState.LIMITED
    assert evidence[0].facts == {"reason": "unsafe_or_invalid_yaml"}


def test_yaml_aliases_above_limit_are_limited(tmp_path: Path) -> None:
    """Catches unbounded YAML alias scanning before safe loading."""
    aliases = ", ".join("*base" for _ in range(51))
    (tmp_path / ".gitlab-ci.yml").write_text(
        f"base: &base {{script: [pytest]}}\nunit-test: [{aliases}]\n", encoding="utf-8"
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))

    assert evidence[0].state is EvidenceState.LIMITED
    assert evidence[0].facts == {"reason": "unsafe_or_invalid_yaml"}


def test_github_workflow_control_keys_are_not_reported_as_jobs(tmp_path: Path) -> None:
    """Catches YAML 1.1 parsing GitHub's unquoted `on` key as a false job."""
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "tests.yml").write_text(
        "name: Tests\non:\n  push:\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps: []\n",
        encoding="utf-8",
    )
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": "github-ci",
            "description": "CI test profile",
            "rules": [
                {
                    "id": "ci.github.publish",
                    "type": "ci_job_exists",
                    "severity": "error",
                    "params": {
                        "ci": "github",
                        "path": ".github/workflows/tests.yml",
                        "job": "publish",
                    },
                    "remediation": "Add the publish job.",
                }
            ],
        }
    )

    evidence = CICollector().collect(AuditContext(tmp_path, offline=True), profile)

    assert evidence[0].facts["jobs"] == ("publish",)


def test_expired_context_fails_before_ci_file_io(tmp_path: Path) -> None:
    """Catches CI collection that ignores the context wall-clock deadline."""
    with pytest.raises(RuntimeFailure, match="timed out"):
        CICollector().collect(
            AuditContext(tmp_path, offline=True, timeout_seconds=-1), load_profile("ai4se-b")
        )
