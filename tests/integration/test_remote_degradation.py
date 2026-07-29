from datetime import UTC, datetime
from pathlib import Path

from repoproof.app import AppDependencies, AuditRequest, run_audit
from repoproof.collectors.github import GitHubCollector
from repoproof.domain import Evidence, EvidenceState, ExitCode, FindingStatus
from repoproof.github import GitHubRequestError, GitHubTokenMissing


class StaticCollector:
    def __init__(self, *evidence: Evidence) -> None:
        self.evidence = evidence

    def collect(self, context: object, profile: object) -> tuple[Evidence, ...]:
        del context, profile
        return self.evidence


class FailingGateway:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.close_calls = 0

    def repository(self, owner: str, repo: str) -> dict[str, object]:
        del owner, repo
        raise self.error

    def merged_pull_request_count(self, owner: str, repo: str) -> int:
        raise AssertionError((owner, repo))

    def has_release(self, owner: str, repo: str) -> bool:
        raise AssertionError((owner, repo))

    def latest_actions_status(self, owner: str, repo: str) -> str | None:
        raise AssertionError((owner, repo))

    def close(self) -> None:
        self.close_calls += 1


def _profile(path: Path) -> Path:
    path.write_text(
        "schema: 1\n"
        "name: remote-test\n"
        "description: remote degradation\n"
        "rules:\n"
        "  - id: docs.required\n"
        "    type: path_exists\n"
        "    severity: error\n"
        "    params: {paths: [REQUIRED.md]}\n"
        "    remediation: Add it.\n"
        "  - id: git.process\n"
        "    type: git_history\n"
        "    severity: warning\n"
        "    params:\n"
        "      min_commits: 1\n"
        "      require_non_default_branch: true\n"
        "      accept_local_merge: false\n"
        "      accept_remote_pr: true\n"
        "    remediation: Preserve a PR.\n",
        encoding="utf-8",
    )
    return path


def _dependencies(gateway: FailingGateway) -> AppDependencies:
    files = Evidence(
        "files.inventory",
        "file_inventory",
        ".",
        EvidenceState.AVAILABLE,
        {"paths": (), "sizes": {}, "total_bytes": 0},
        {},
    )
    git = Evidence(
        "git:history",
        "git_history",
        ".",
        EvidenceState.AVAILABLE,
        {
            "is_repository": True,
            "current_branch": "feature",
            "default_branch": "main",
            "commit_count": 2,
            "branches": ("feature", "main"),
            "merge_count": 0,
            "repository_slug": "owner/repo",
        },
        {},
    )
    return AppDependencies(
        collectors={
            "files": StaticCollector(files),
            "git": StaticCollector(git),
        },
        clock=lambda: datetime(2026, 7, 29, tzinfo=UTC),
        monotonic_ns=iter(range(20)).__next__,
        github_collector_factory=lambda slug: GitHubCollector(gateway, slug),
    )


def test_missing_token_skips_remote_rule_without_runtime_exit(tmp_path: Path) -> None:
    """Catches absent optional credentials being promoted to a runtime failure."""
    gateway = FailingGateway(GitHubTokenMissing())

    report = run_audit(
        AuditRequest(tmp_path, str(_profile(tmp_path / "profile.yml")), False),
        _dependencies(gateway),
    )

    remote = next(finding for finding in report.findings if finding.rule_id == "git.process")
    assert remote.status is FindingStatus.SKIP
    assert report.exit_code is ExitCode.FINDINGS
    assert gateway.close_calls == 1


def test_network_failure_preserves_local_findings_and_exits_three(tmp_path: Path) -> None:
    """Catches remote failure discarding local findings or returning an ordinary audit exit."""
    gateway = FailingGateway(GitHubRequestError())

    report = run_audit(
        AuditRequest(tmp_path, str(_profile(tmp_path / "profile.yml")), False),
        _dependencies(gateway),
    )

    local = next(finding for finding in report.findings if finding.rule_id == "docs.required")
    assert local.status is FindingStatus.FAIL
    assert report.exit_code is ExitCode.RUNTIME
    assert report.diagnostics == ("github: remote evidence unavailable",)
    assert gateway.close_calls == 1
