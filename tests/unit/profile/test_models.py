import subprocess
import sys

import pytest
from pydantic import ValidationError

from repoproof.profile.models import Profile

BASE = {
    "schema": 1,
    "name": "team-policy",
    "description": "Team release checks",
    "rules": [
        {
            "id": "docs.spec",
            "type": "path_exists",
            "severity": "error",
            "params": {"paths": ["SPEC.md"], "min_matches": 1},
            "remediation": "Add SPEC.md.",
        }
    ],
}


def test_profile_model_imports_with_warnings_as_errors() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", "import repoproof.profile.models"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_profile_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Profile.model_validate(BASE | {"command": "rm -rf ."})


def test_profile_rejects_duplicate_rule_ids() -> None:
    duplicate = BASE | {"rules": [BASE["rules"][0], BASE["rules"][0]]}

    with pytest.raises(ValidationError, match="duplicate rule id"):
        Profile.model_validate(duplicate)


def test_profile_rejects_unknown_rule_type() -> None:
    invalid = BASE | {"rules": [BASE["rules"][0] | {"type": "python_eval"}]}

    with pytest.raises(ValidationError, match="union_tag_invalid"):
        Profile.model_validate(invalid)


@pytest.mark.parametrize("path", ["../secret.txt", "/etc/passwd", r"C:\\Users\\secret.txt"])
def test_profile_rejects_unsafe_repository_paths(path: str) -> None:
    invalid = BASE | {
        "rules": [
            {
                **BASE["rules"][0],
                "params": {"paths": [path], "min_matches": 1},
            }
        ]
    }

    with pytest.raises(ValidationError, match="relative"):
        Profile.model_validate(invalid)
