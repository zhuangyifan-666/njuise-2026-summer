import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import RepositoryFile
from repoproof.collectors.secrets import SecretCollector
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile

CANARY = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"


def _collect(root: Path, **context_values: object):
    return SecretCollector().collect(
        AuditContext(root, offline=True, **context_values), load_profile("ai4se-b")
    )[0]


def test_token_match_contains_only_safe_metadata(tmp_path: Path) -> None:
    """Catches evidence that retains a detected token instead of only its fingerprint."""
    (tmp_path / "config.txt").write_text(f"token = '{CANARY}'\n", encoding="utf-8")

    evidence = _collect(tmp_path)
    match = evidence.facts["matches"][0]

    assert match == {
        "category": "token",
        "path": "config.txt",
        "line": 1,
        "fingerprint": hashlib.sha256(CANARY.encode()).hexdigest()[:8],
        "allowlisted_for": (),
    }
    assert CANARY not in repr(evidence)


def test_private_key_and_sensitive_filename_are_detected(tmp_path: Path) -> None:
    """Catches omission of either a private-key marker or sensitive file-name signal."""
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nfixture-body\n", encoding="utf-8"
    )

    evidence = _collect(tmp_path)

    assert {item["category"] for item in evidence.facts["matches"]} == {
        "private_key",
        "sensitive_file",
    }


def test_excluded_path_never_reads_or_reports_canary(tmp_path: Path) -> None:
    """Catches scanning that ignores a secret rule's configured exclusion patterns."""
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text(CANARY, encoding="utf-8")

    evidence = _collect(tmp_path)

    assert evidence.facts["matches"] == ()
    assert CANARY not in repr(evidence)


def test_allowlist_marks_only_matching_rule_path_and_fingerprint(tmp_path: Path) -> None:
    """Catches allowlist matching that disregards its rule, relative path, or fingerprint."""
    target = tmp_path / "fixture.txt"
    target.write_text(CANARY, encoding="utf-8")
    fingerprint = hashlib.sha256(CANARY.encode()).hexdigest()[:8]
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: fixture.txt\n"
        f"    fingerprint: {fingerprint}\n",
        encoding="utf-8",
    )

    evidence = _collect(tmp_path)
    token = next(item for item in evidence.facts["matches"] if item["category"] == "token")

    assert token["allowlisted_for"] == ("security.secrets",)
    assert CANARY not in repr(evidence)


def test_binary_and_oversize_files_are_not_read(tmp_path: Path) -> None:
    """Catches scanner reads that ignore binary and per-file read bounds."""
    (tmp_path / "binary.bin").write_bytes(b"\x00" + CANARY.encode())
    (tmp_path / "large.txt").write_text(CANARY, encoding="utf-8")

    evidence = _collect(tmp_path, max_read_bytes=len(CANARY) - 1)

    assert evidence.facts["matches"] == ()
    assert CANARY not in repr(evidence)


def test_read_limit_is_enforced_even_when_file_metadata_is_stale(tmp_path: Path) -> None:
    """Catches a time-of-check/read gap that lets a grown file bypass the byte limit."""
    target = tmp_path / "config.txt"
    target.write_text(CANARY, encoding="utf-8")
    stale_entry = RepositoryFile("config.txt", target, 0)

    with patch("repoproof.collectors.secrets.repository_files", return_value=(stale_entry,)):
        evidence = _collect(tmp_path, max_read_bytes=len("ghp_") + 19)

    assert evidence.facts["matches"] == ()


def test_external_link_and_candidate_limit_are_rejected_before_scanning(tmp_path: Path) -> None:
    """Catches traversal that scans a link or continues beyond the candidate limit."""
    outside = tmp_path / "outside.txt"
    outside.write_text(CANARY, encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    (root / "one.txt").write_text("ok", encoding="utf-8")
    (root / "two.txt").write_text("ok", encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="candidate file limit"):
        _collect(root, max_files=1)


def test_expired_context_stops_before_opening_candidate(tmp_path: Path) -> None:
    """Catches scanner deadline checks that start only after file content is opened."""
    (tmp_path / "config.txt").write_text(CANARY, encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="timed out"):
        _collect(tmp_path, timeout_seconds=0.0)
