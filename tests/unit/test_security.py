from pathlib import Path

import pytest

from repoproof.errors import UsageFailure
from repoproof.security import (
    SafeOpenFailure,
    open_regular_file,
    redact_text,
    resolve_under_root,
    short_fingerprint,
)


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    """Catches a resolver change that permits profile paths to escape via '..'."""
    root = tmp_path / "repo"
    root.mkdir()

    with pytest.raises(UsageFailure, match="outside repository"):
        resolve_under_root(root, "../outside.txt")


def test_absolute_profile_path_is_rejected(tmp_path: Path) -> None:
    """Catches a resolver change that accepts host-absolute profile paths."""
    root = tmp_path / "repo"
    root.mkdir()

    with pytest.raises(UsageFailure, match="relative"):
        resolve_under_root(root, str((tmp_path / "secret").resolve()))


def test_redact_text_replaces_longer_overlapping_secret_first() -> None:
    """Catches redaction that exposes suffixes when secrets overlap."""
    assert redact_text("token=abc123", ("abc", "abc123")) == "token=<redacted>"


def test_short_fingerprint_is_stable_eight_character_sha256_prefix() -> None:
    """Catches fingerprint changes that lose deterministic short SHA-256 identity."""
    assert short_fingerprint(b"repoproof") == "768eeb38"


def test_safe_open_rejects_final_symlink_without_returning_a_handle(tmp_path: Path) -> None:
    """Catches safe opening that follows a replaced final symlink before validation."""
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (root / "candidate.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(SafeOpenFailure):
        open_regular_file(root, "candidate.txt")
