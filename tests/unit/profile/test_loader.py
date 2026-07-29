import hashlib
import json
from pathlib import Path

import pytest

from repoproof.errors import UsageFailure
from repoproof.profile.loader import MAX_PROFILE_BYTES, _read_profile, load_profile, profile_hash


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


def test_profile_dump_and_hash_use_the_public_schema_alias() -> None:
    profile = load_profile("ai4se-b")
    public = profile.model_dump(mode="json")
    public_hash = hashlib.sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    assert profile.schema == 1
    assert public["schema"] == 1
    assert "profile_schema" not in public
    assert profile_hash(profile) == public_hash


def test_builtin_profile_size_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    class OversizedBuiltinResource:
        def joinpath(self, name: str) -> "OversizedBuiltinResource":
            assert name == "ai4se-b.yml"
            return self

        def read_bytes(self) -> bytes:
            return b"x" * (MAX_PROFILE_BYTES + 1)

    monkeypatch.setattr(
        "repoproof.profile.loader.files", lambda _: OversizedBuiltinResource()
    )

    with pytest.raises(UsageFailure, match="exceeds 1 MiB"):
        _read_profile("ai4se-b")
