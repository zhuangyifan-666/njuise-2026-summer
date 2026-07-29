import hashlib
import json
from pathlib import Path

import pytest

from repoproof.errors import UsageFailure
from repoproof.profile.loader import load_profile, profile_hash


def test_builtin_profile_has_schema_one_and_six_rule_types() -> None:
    profile = load_profile("ai4se-b")

    assert profile.schema == 1
    assert {rule.type for rule in profile.rules} == {
        "path_exists",
        "markdown_sections",
        "ci_job_exists",
        "git_history",
        "distribution_ready",
        "secret_scan",
    }


def test_alias_limit_is_enforced(tmp_path: Path) -> None:
    aliases = "\n".join(f"  x{i}: *base" for i in range(51))
    policy = tmp_path / "aliases.yml"
    policy.write_text(f"schema: &base 1\nname: policy\ndescription: x\n{aliases}\nrules: []\n")

    with pytest.raises(UsageFailure, match="50 YAML aliases"):
        load_profile(str(policy))


def test_hash_is_stable_for_same_semantics() -> None:
    first = load_profile("ai4se-b")
    second = load_profile("ai4se-b")

    assert profile_hash(first) == profile_hash(second)


def test_profile_hash_uses_the_public_schema_alias() -> None:
    profile = load_profile("ai4se-b")
    public = profile.model_dump(mode="json", by_alias=True)
    internal = profile.model_dump(mode="json")
    internal_hash = hashlib.sha256(
        json.dumps(internal, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    assert profile.schema == 1
    assert public["schema"] == 1
    assert "profile_schema" not in public
    assert profile_hash(profile) != internal_hash
