from pathlib import Path

import pytest

from repoproof.errors import UsageFailure
from repoproof.security import redact_text, resolve_under_root, short_fingerprint


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
