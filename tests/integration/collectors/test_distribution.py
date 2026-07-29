from pathlib import Path

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.distribution import DistributionCollector
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile


def test_python_packaging_and_release_workflow_are_detected(tmp_path: Path) -> None:
    """Catches static distribution inspection that misses a release-named workflow."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "repoproof.spec").write_text("a = Analysis([])\n", encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "release.yml").write_text("on:\n  push:\n    tags: ['v*']\n", encoding="utf-8")

    evidence = DistributionCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )[0]

    assert evidence.facts["packaging"] == ("python",)
    assert evidence.facts["release_workflow"] is True


def test_partial_packaging_configuration_is_not_claimed(tmp_path: Path) -> None:
    """Catches distribution evidence that reports Python packaging without its spec file."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    evidence = DistributionCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )[0]

    assert evidence.facts["packaging"] == ()
    assert evidence.facts["release_workflow"] is False


def test_release_named_test_workflow_is_not_claimed_as_release_evidence(tmp_path: Path) -> None:
    """Catches filename-only release evidence from a workflow with no release trigger."""
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "release.yml").write_text(
        "name: Tests\njobs:\n  unit:\n    runs-on: ubuntu-latest\n    steps: []\n",
        encoding="utf-8",
    )

    evidence = DistributionCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )[0]

    assert evidence.facts["release_workflow"] is False


def test_workflow_collection_respects_candidate_limit(tmp_path: Path) -> None:
    """Catches unbounded static workflow scanning beyond the configured candidate limit."""
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "first.yml").write_text("on:\n  push:\n", encoding="utf-8")
    (workflow / "second.yml").write_text("on:\n  push:\n", encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="candidate file limit"):
        DistributionCollector().collect(
            AuditContext(tmp_path, offline=True, max_files=1), load_profile("ai4se-b")
        )


def test_expired_context_fails_before_distribution_file_checks(tmp_path: Path) -> None:
    """Catches static distribution collection that ignores the context deadline."""
    with pytest.raises(RuntimeFailure, match="timed out"):
        DistributionCollector().collect(
            AuditContext(tmp_path, offline=True, timeout_seconds=-1), load_profile("ai4se-b")
        )
