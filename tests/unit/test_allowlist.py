from pathlib import Path

import pytest

from repoproof.allowlist import load_secret_allowlist
from repoproof.errors import UsageFailure


def test_allowlist_accepts_only_rule_path_and_short_fingerprint(tmp_path: Path) -> None:
    """Catches schema changes that permit identities beyond rule/path/fingerprint."""
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: tests/fixture.txt\n"
        "    fingerprint: 1a2b3c4d\n",
        encoding="utf-8",
    )

    assert load_secret_allowlist(tmp_path) == frozenset(
        {("security.secrets", "tests/fixture.txt", "1a2b3c4d")}
    )


def test_allowlist_rejects_raw_value_field_without_disclosing_it(tmp_path: Path) -> None:
    """Catches validation errors that preserve an allowlisted raw credential value."""
    raw_value = "never-allowed-raw-value"
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: x\n"
        "    fingerprint: 1a2b3c4d\n"
        f"    value: {raw_value}\n",
        encoding="utf-8",
    )

    with pytest.raises(UsageFailure, match="allowlist") as error:
        load_secret_allowlist(tmp_path)

    assert raw_value not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_allowlist_rejects_external_symlink_without_reading_it(tmp_path: Path) -> None:
    """Catches allowlist loading that follows a link outside the audit root."""
    outside = tmp_path / "outside.yml"
    outside.write_text("schema: 1\nentries: []\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / ".repoproofallowlist.yml").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(UsageFailure, match="allowlist") as error:
        load_secret_allowlist(root)

    assert "outside.yml" not in str(error.value)
