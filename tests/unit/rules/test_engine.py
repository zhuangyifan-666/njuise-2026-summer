from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate, required_collector_names


def profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate(
        {"schema": 1, "name": "test-policy", "description": "test", "rules": [rule]}
    )


def test_missing_error_path_is_fail() -> None:
    policy = profile(
        {
            "id": "docs.spec",
            "type": "path_exists",
            "severity": "error",
            "params": {"paths": ["SPEC.md"], "min_matches": 1},
            "remediation": "Add it.",
        }
    )
    evidence = Evidence(
        "files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE, {"paths": ()}, {}
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.FAIL


def test_missing_warning_path_is_warn() -> None:
    policy = profile(
        {
            "id": "ci.github",
            "type": "path_exists",
            "severity": "warning",
            "params": {"paths": [".github/workflows/*.yml"], "min_matches": 1},
            "remediation": "Add it.",
        }
    )
    evidence = Evidence(
        "files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE, {"paths": ()}, {}
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.WARN


def test_unavailable_file_inventory_skips_instead_of_failing() -> None:
    policy = profile(
        {
            "id": "docs.spec",
            "type": "path_exists",
            "severity": "error",
            "params": {"paths": ["SPEC.md"]},
            "remediation": "Add it.",
        }
    )
    evidence = Evidence("files.inventory", "file_inventory", ".", EvidenceState.LIMITED, {}, {})
    assert evaluate(policy, [evidence])[0].status is FindingStatus.SKIP


def test_collector_selection_is_minimal_sorted_and_offline_never_requests_github() -> None:
    policy = Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test",
            "rules": [
                {
                    "id": "docs.spec",
                    "type": "path_exists",
                    "severity": "error",
                    "params": {"paths": ["SPEC.md"]},
                    "remediation": "Add it.",
                },
                {
                    "id": "git.process",
                    "type": "git_history",
                    "severity": "warning",
                    "params": {"min_commits": 1, "accept_remote_pr": True},
                    "remediation": "Add process evidence.",
                },
                {
                    "id": "dist.release",
                    "type": "distribution_ready",
                    "severity": "error",
                    "params": {
                        "allowed": ["python"],
                        "require_release_workflow": False,
                        "accept_published_release": True,
                    },
                    "remediation": "Add release.",
                },
            ],
        }
    )
    assert required_collector_names(policy, offline=False) == ("distribution", "files", "git")
    assert required_collector_names(policy, offline=True) == ("distribution", "files", "git")


def test_path_only_policy_needs_only_file_inventory() -> None:
    policy = profile(
        {
            "id": "docs.spec",
            "type": "path_exists",
            "severity": "error",
            "params": {"paths": ["SPEC.md"]},
            "remediation": "Add it.",
        }
    )
    assert required_collector_names(policy, offline=False) == ("files",)


def test_distribution_required_paths_request_file_inventory() -> None:
    policy = profile(
        {
            "id": "dist.release",
            "type": "distribution_ready",
            "severity": "error",
            "params": {"allowed": ["python"], "required_paths": ["pyproject.toml"]},
            "remediation": "Add packaging.",
        }
    )
    assert required_collector_names(policy, offline=True) == ("distribution", "files")


def test_github_is_selected_only_for_a_process_or_release_alternative() -> None:
    policy = Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test",
            "rules": [
                {
                    "id": "git.process",
                    "type": "git_history",
                    "severity": "error",
                    "params": {
                        "min_commits": 1,
                        "require_non_default_branch": True,
                        "accept_remote_pr": True,
                    },
                    "remediation": "Add process.",
                },
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
                },
            ],
        }
    )
    assert required_collector_names(policy, offline=False) == (
        "distribution",
        "git",
        "github",
    )
