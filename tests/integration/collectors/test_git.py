import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from repoproof.collectors.base import AuditContext
from repoproof.collectors.git import GitCollector, GitRunner
from repoproof.domain import EvidenceState
from repoproof.profile.loader import load_profile


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


def test_git_history_counts_commits_and_merges(tmp_path: Path) -> None:
    """Catches Git history evidence that omits merge commits or local branches."""
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    git(tmp_path, "add", "a.txt")
    git(tmp_path, "commit", "-m", "first")
    git(tmp_path, "checkout", "-b", "feature")
    (tmp_path / "feature.txt").write_text("feature", encoding="utf-8")
    git(tmp_path, "add", "feature.txt")
    git(tmp_path, "commit", "-m", "feature")
    git(tmp_path, "checkout", "main")
    git(tmp_path, "merge", "--no-ff", "feature", "-m", "merge feature")

    evidence = GitCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]

    assert evidence.state is EvidenceState.AVAILABLE
    assert evidence.facts == {
        "is_repository": True,
        "current_branch": "main",
        "default_branch": "main",
        "commit_count": 3,
        "branches": ("feature", "main"),
        "merge_count": 1,
        "repository_slug": None,
    }
    assert evidence.provenance["collector"] == "git"


def test_missing_git_returns_unavailable_evidence(tmp_path: Path) -> None:
    """Catches a missing Git executable escaping as an unsanitized system error."""
    collector = GitCollector(GitRunner(executable="missing-git-for-repoproof"))

    evidence = collector.collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]

    assert evidence.state is EvidenceState.UNAVAILABLE
    assert evidence.facts == {"reason": "git_unavailable_or_not_repository"}


class _DeadlineRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, root: Path, args: tuple[str, ...], timeout: float, max_output: int) -> str:
        del root, timeout, max_output
        self.calls.append(args)
        return "true"


def test_git_collection_stops_when_the_shared_audit_deadline_expires(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """Catches five individually-timed Git commands exceeding one audit deadline."""
    runner = _DeadlineRunner()
    moments = iter((10.0, 10.5, 12.0))
    monkeypatch.setattr("repoproof.collectors.git.time.monotonic", lambda: next(moments))

    evidence = GitCollector(runner).collect(
        AuditContext(tmp_path, True, timeout_seconds=1.0), load_profile("ai4se-b")
    )[0]

    assert runner.calls == [("rev-parse", "--is-inside-work-tree")]
    assert evidence.state is EvidenceState.UNAVAILABLE
    assert evidence.facts == {"reason": "git_unavailable_or_not_repository"}
