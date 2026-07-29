from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile
from repoproof.rules import evaluate


def test_evaluation_is_repeatable_with_reordered_duplicate_and_mapping_evidence() -> None:
    policy = Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test",
            "rules": [
                {
                    "id": "z.path",
                    "type": "path_exists",
                    "severity": "error",
                    "params": {"paths": ["SPEC.md"]},
                    "remediation": "Add it.",
                },
                {
                    "id": "a.secret",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["token"], "exclude_paths": []},
                    "remediation": "Remove it.",
                },
            ],
        }
    )
    files = Evidence(
        "files.inventory",
        "file_inventory",
        ".",
        EvidenceState.AVAILABLE,
        {"paths": {"SPEC.md"}},
        {},
    )
    duplicate_files = Evidence(
        "z.files", "file_inventory", ".", EvidenceState.AVAILABLE, {"paths": ()}, {}
    )
    secrets = Evidence(
        "secrets:scan", "secret_scan", ".", EvidenceState.AVAILABLE, {"matches": ()}, {}
    )
    first = evaluate(policy, (files, duplicate_files, secrets))
    second = evaluate(policy, (secrets, duplicate_files, files))
    assert first == second
    assert [finding.rule_id for finding in first] == ["a.secret", "z.path"]


def test_duplicate_secret_matches_have_canonical_locations_and_details() -> None:
    policy = Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test",
            "rules": [
                {
                    "id": "security.secrets",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["token"], "exclude_paths": []},
                    "remediation": "Remove it.",
                }
            ],
        }
    )
    evidence = Evidence(
        "secrets:scan",
        "secret_scan",
        ".",
        EvidenceState.AVAILABLE,
        {
            "matches": (
                {
                    "category": "token",
                    "path": "z.py",
                    "line": 2,
                    "fingerprint": "b",
                    "triggered_for": ("security.secrets",),
                    "allowlisted_for": (),
                },
                {
                    "category": "token",
                    "path": "a.py",
                    "line": 1,
                    "fingerprint": "a",
                    "triggered_for": ("security.secrets",),
                    "allowlisted_for": (),
                },
                {
                    "category": "token",
                    "path": "z.py",
                    "line": 2,
                    "fingerprint": "b",
                    "triggered_for": ("security.secrets",),
                    "allowlisted_for": (),
                },
            )
        },
        {},
    )
    finding = evaluate(policy, (evidence,))[0]
    assert [(location.path, location.line) for location in finding.locations] == [
        ("a.py", 1),
        ("z.py", 2),
    ]
    assert finding.message.index("fingerprint=a") < finding.message.index("fingerprint=b")
