import pytest

from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate


def profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate(
        {"schema": 1, "name": "test-policy", "description": "test", "rules": [rule]}
    )


@pytest.mark.parametrize(
    ("rule", "evidence", "expected"),
    [
        (
            {
                "id": "ci.job",
                "type": "ci_job_exists",
                "severity": "error",
                "params": {"ci": "gitlab", "path": ".gitlab-ci.yml", "job": "unit-test"},
                "remediation": "Add job.",
            },
            Evidence(
                "ci:gitlab:.gitlab-ci.yml",
                "ci_config",
                ".gitlab-ci.yml",
                EvidenceState.AVAILABLE,
                {"jobs": ("unit-test",)},
                {},
            ),
            FindingStatus.PASS,
        ),
        (
            {
                "id": "git.history",
                "type": "git_history",
                "severity": "error",
                "params": {"min_commits": 5},
                "remediation": "Add commits.",
            },
            Evidence("git:history", "git_history", ".", EvidenceState.UNAVAILABLE, {}, {}),
            FindingStatus.SKIP,
        ),
        (
            {
                "id": "dist.release",
                "type": "distribution_ready",
                "severity": "error",
                "params": {
                    "allowed": ["python"],
                    "required_paths": ["pyproject.toml"],
                    "require_release_workflow": True,
                    "accept_published_release": True,
                },
                "remediation": "Add release.",
            },
            Evidence(
                "distribution:local",
                "distribution",
                ".",
                EvidenceState.AVAILABLE,
                {"packaging": ("python",), "release_workflow": True},
                {},
            ),
            FindingStatus.PASS,
        ),
        (
            {
                "id": "security.secrets",
                "type": "secret_scan",
                "severity": "error",
                "params": {"categories": ["token"], "entropy_threshold": 4.0, "exclude_paths": []},
                "remediation": "Remove it.",
            },
            Evidence(
                "secrets:scan",
                "secret_scan",
                ".",
                EvidenceState.AVAILABLE,
                {
                    "matches": (
                        {
                            "category": "token",
                            "path": "x",
                            "line": 1,
                            "fingerprint": "12345678",
                            "allowlisted_for": (),
                        },
                    )
                },
                {},
            ),
            FindingStatus.FAIL,
        ),
    ],
)
def test_rule_matrix(rule: dict[str, object], evidence: Evidence, expected: FindingStatus) -> None:
    assert evaluate(profile(rule), [evidence])[0].status is expected


def test_missing_ci_job_is_warning() -> None:
    policy = profile(
        {
            "id": "ci.job",
            "type": "ci_job_exists",
            "severity": "warning",
            "params": {"ci": "github", "path": ".github/workflows/test.yml", "job": "test"},
            "remediation": "Add job.",
        }
    )
    evidence = Evidence(
        "ci:github:.github/workflows/test.yml",
        "ci_config",
        ".github/workflows/test.yml",
        EvidenceState.AVAILABLE,
        {"jobs": ()},
        {},
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.WARN


def test_git_local_false_evidence_fails_even_when_remote_is_not_requested() -> None:
    policy = profile(
        {
            "id": "git.process",
            "type": "git_history",
            "severity": "error",
            "params": {
                "min_commits": 1,
                "require_non_default_branch": True,
                "accept_local_merge": True,
            },
            "remediation": "Add process.",
        }
    )
    evidence = Evidence(
        "git:history",
        "git_history",
        ".",
        EvidenceState.AVAILABLE,
        {
            "commit_count": 3,
            "default_branch": "main",
            "branches": ("main", "feature"),
            "merge_count": 0,
        },
        {},
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.FAIL


def test_git_remote_unavailable_skips_when_remote_process_is_required_for_a_possible_pass() -> None:
    policy = profile(
        {
            "id": "git.process",
            "type": "git_history",
            "severity": "error",
            "params": {
                "min_commits": 1,
                "require_non_default_branch": True,
                "accept_local_merge": False,
                "accept_remote_pr": True,
            },
            "remediation": "Add process.",
        }
    )
    local = Evidence(
        "git:history",
        "git_history",
        ".",
        EvidenceState.AVAILABLE,
        {
            "commit_count": 3,
            "default_branch": "main",
            "branches": ("main", "feature"),
            "merge_count": 0,
        },
        {},
    )
    remote = Evidence(
        "github:repository", "github_repository", ".", EvidenceState.UNAVAILABLE, {}, {}
    )
    assert evaluate(policy, [local, remote])[0].status is FindingStatus.SKIP


def test_git_remote_false_evidence_fails() -> None:
    policy = profile(
        {
            "id": "git.process",
            "type": "git_history",
            "severity": "error",
            "params": {
                "min_commits": 1,
                "require_non_default_branch": True,
                "accept_local_merge": False,
                "accept_remote_pr": True,
            },
            "remediation": "Add process.",
        }
    )
    local = Evidence(
        "git:history",
        "git_history",
        ".",
        EvidenceState.AVAILABLE,
        {
            "commit_count": 3,
            "default_branch": "main",
            "branches": ("main", "feature"),
            "merge_count": 0,
        },
        {},
    )
    remote = Evidence(
        "github:repository",
        "github_repository",
        ".",
        EvidenceState.AVAILABLE,
        {"merged_pull_requests": 0},
        {},
    )
    assert evaluate(policy, [local, remote])[0].status is FindingStatus.FAIL


def test_distribution_remote_unavailable_skips_but_known_false_remote_fails() -> None:
    policy = profile(
        {
            "id": "dist.release",
            "type": "distribution_ready",
            "severity": "error",
            "params": {
                "allowed": ["python"],
                "require_release_workflow": True,
                "accept_published_release": True,
            },
            "remediation": "Add release.",
        }
    )
    local = Evidence(
        "distribution:local",
        "distribution",
        ".",
        EvidenceState.AVAILABLE,
        {"packaging": ("python",), "release_workflow": False},
        {},
    )
    unavailable = Evidence(
        "github:repository", "github_repository", ".", EvidenceState.UNAVAILABLE, {}, {}
    )
    false_remote = Evidence(
        "github:repository",
        "github_repository",
        ".",
        EvidenceState.AVAILABLE,
        {"has_release": False},
        {},
    )
    assert evaluate(policy, [local, unavailable])[0].status is FindingStatus.SKIP
    assert evaluate(policy, [local, false_remote])[0].status is FindingStatus.FAIL


def test_secret_message_never_contains_raw_value_and_respects_rule_allowlist() -> None:
    policy = profile(
        {
            "id": "security.secrets",
            "type": "secret_scan",
            "severity": "error",
            "params": {"categories": ["token"], "exclude_paths": []},
            "remediation": "Remove it.",
        }
    )
    leaked = "ghp_very_secret_raw_value"
    evidence = Evidence(
        "secrets:scan",
        "secret_scan",
        ".",
        EvidenceState.AVAILABLE,
        {
            "matches": (
                {
                    "category": "token",
                    "path": "src/x.py",
                    "line": 9,
                    "fingerprint": "deadbeef",
                    "raw": leaked,
                    "allowlisted_for": (),
                },
            )
        },
        {},
    )
    finding = evaluate(policy, [evidence])[0]
    assert finding.status is FindingStatus.FAIL
    assert leaked not in finding.message
    assert "deadbeef" in finding.message
    assert finding.locations[0].path == "src/x.py"

    allowlisted = Evidence(
        "secrets:scan",
        "secret_scan",
        ".",
        EvidenceState.AVAILABLE,
        {
            "matches": (
                {
                    "category": "token",
                    "path": "src/x.py",
                    "line": 9,
                    "fingerprint": "deadbeef",
                    "allowlisted_for": ("security.secrets",),
                },
            )
        },
        {},
    )
    assert evaluate(policy, [allowlisted])[0].status is FindingStatus.PASS
