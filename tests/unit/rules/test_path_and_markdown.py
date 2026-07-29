from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate


def profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate(
        {"schema": 1, "name": "test-policy", "description": "test", "rules": [rule]}
    )


def test_path_globs_count_unique_matches_and_record_sorted_locations() -> None:
    policy = profile(
        {
            "id": "docs.required",
            "type": "path_exists",
            "severity": "error",
            "params": {"paths": ["*.md", "README.*"], "min_matches": 2},
            "remediation": "Add docs.",
        }
    )
    evidence = Evidence(
        "files.inventory",
        "file_inventory",
        ".",
        EvidenceState.AVAILABLE,
        {"paths": ("README.md", "PLAN.md", "README.md")},
        {},
    )
    finding = evaluate(policy, [evidence])[0]
    assert finding.status is FindingStatus.PASS
    assert [location.path for location in finding.locations] == ["PLAN.md", "README.md"]


def test_markdown_alias_and_completed_hash_pass() -> None:
    policy = profile(
        {
            "id": "docs.readme",
            "type": "markdown_sections",
            "severity": "error",
            "params": {
                "path": "README.md",
                "headings": ["安装"],
                "aliases": {"安装": ["Installation"]},
                "completed_items_require_commit": True,
            },
            "remediation": "Fix README.",
        }
    )
    evidence = Evidence(
        "markdown:README.md",
        "markdown",
        "README.md",
        EvidenceState.AVAILABLE,
        {"headings": ("installation",), "completed_items": ({"line": 4, "has_commit": True},)},
        {},
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.PASS


def test_completed_item_without_hash_warns_at_exact_line() -> None:
    policy = profile(
        {
            "id": "plan.evidence",
            "type": "markdown_sections",
            "severity": "warning",
            "params": {"path": "PLAN.md", "completed_items_require_commit": True},
            "remediation": "Add commit hash.",
        }
    )
    evidence = Evidence(
        "markdown:PLAN.md",
        "markdown",
        "PLAN.md",
        EvidenceState.AVAILABLE,
        {"headings": (), "completed_items": ({"line": 8, "has_commit": False},)},
        {},
    )
    finding = evaluate(policy, [evidence])[0]
    assert finding.status is FindingStatus.WARN
    assert finding.locations[0].line == 8


def test_markdown_limited_evidence_skips_instead_of_failing() -> None:
    policy = profile(
        {
            "id": "docs.readme",
            "type": "markdown_sections",
            "severity": "error",
            "params": {"path": "README.md", "headings": ["Overview"]},
            "remediation": "Fix README.",
        }
    )
    evidence = Evidence(
        "markdown:README.md", "markdown", "README.md", EvidenceState.LIMITED, {}, {}
    )
    assert evaluate(policy, [evidence])[0].status is FindingStatus.SKIP
