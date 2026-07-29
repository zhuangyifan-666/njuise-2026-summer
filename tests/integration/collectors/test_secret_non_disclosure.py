import hashlib
import io
import traceback
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import RepositoryFile
from repoproof.collectors.secrets import _READ_CHUNK_BYTES, SecretCollector
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile
from repoproof.profile.models import Profile
from repoproof.security import SafeRegularFile

CANARY = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"


def _collect(root: Path, **context_values: object):
    return SecretCollector().collect(
        AuditContext(root, offline=True, **context_values), load_profile("ai4se-b")
    )[0]


def _traceback_contains(exception: BaseException, marker: str) -> bool:
    trace = exception.__traceback__
    while trace is not None:
        filename = trace.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/repoproof/" in filename and any(
            marker in repr(value) for value in trace.tb_frame.f_locals.values()
        ):
            return True
        trace = trace.tb_next
    detailed = traceback.TracebackException.from_exception(exception, capture_locals=True)
    return any(
        "/src/repoproof/" in frame.filename.replace("\\", "/")
        and marker in repr(frame.locals)
        for frame in detailed.stack
    )


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


def test_classifier_failure_traceback_never_retains_candidate_text(tmp_path: Path) -> None:
    """Catches raw candidate/window locals escaping through classifier failures."""
    marker = "scanner-traceback-canary"
    (tmp_path / "config.txt").write_text(f"token = '{CANARY}'\n{marker}\n", encoding="utf-8")

    with patch.object(SecretCollector, "_classify", side_effect=RuntimeError(marker)):
        with pytest.raises(RuntimeFailure) as error:
            _collect(tmp_path)

    assert not _traceback_contains(error.value, marker)


def test_read_failure_traceback_never_retains_candidate_text(tmp_path: Path) -> None:
    """Catches a raw reader failure that escapes from the raw-processing helper."""
    marker = "read-traceback-canary"
    target = tmp_path / "config.txt"
    target.write_text("placeholder", encoding="utf-8")

    class BrokenStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise OSError(marker)

    opened = SafeRegularFile(BrokenStream(), 0)
    with patch("repoproof.collectors.secrets.open_regular_file", return_value=opened):
        with pytest.raises(RuntimeFailure) as error:
            _collect(tmp_path)

    assert not _traceback_contains(error.value, marker)


def test_timeout_traceback_never_retains_candidate_text(tmp_path: Path) -> None:
    """Catches timeout propagation from a frame that has already read raw content."""
    marker = "timeout-traceback-canary"
    (tmp_path / "config.txt").write_text(CANARY + marker, encoding="utf-8")

    with patch(
        "repoproof.collectors.secrets._raise_if_timed_out",
        side_effect=[None, None, RuntimeFailure(marker, "test-only")],
    ):
        with pytest.raises(RuntimeFailure) as error:
            _collect(tmp_path)

    assert not _traceback_contains(error.value, marker)


def test_stale_inventory_with_complete_token_and_trailing_growth_is_discarded(
    tmp_path: Path,
) -> None:
    """Catches descriptor-size checks that trust stale inventory over opened content."""
    target = tmp_path / "config.txt"
    target.write_text(CANARY + "\n" + ("x" * 40), encoding="utf-8")
    stale_entry = RepositoryFile("config.txt", target, len(CANARY))

    with patch("repoproof.collectors.secrets.repository_files", return_value=(stale_entry,)):
        evidence = _collect(tmp_path, max_read_bytes=len(CANARY))

    assert evidence.facts["matches"] == ()


def test_max_length_token_split_across_read_boundary_has_one_fingerprint(tmp_path: Path) -> None:
    """Catches chunk-boundary scanners that drop or duplicate a maximum-length token."""
    token = b"ghp_" + (b"a" * 255)
    target = tmp_path / "config.txt"
    target.write_bytes((b"x" * (_READ_CHUNK_BYTES - 2)) + b" " + token + b"\n")

    evidence = _collect(tmp_path)
    token_matches = [item for item in evidence.facts["matches"] if item["category"] == "token"]

    assert [item["fingerprint"] for item in token_matches] == [
        hashlib.sha256(token).hexdigest()[:8]
    ]


def test_private_key_and_assignment_split_across_boundaries_are_not_truncated(
    tmp_path: Path,
) -> None:
    """Catches boundary handling that loses private-key or assignment suffixes."""
    assignment = b"password=" + (b"A1b2C3d4E5f6G7h8I9j0" * 2)
    payload = (
        (b"x" * (_READ_CHUNK_BYTES - 10))
        + b"-----BEGIN RSA PRIVATE KEY-----\n"
        + (b"y" * (_READ_CHUNK_BYTES - 5))
        + assignment
        + b"\n"
    )
    (tmp_path / "config.txt").write_bytes(payload)

    evidence = _collect(tmp_path)

    assert {item["category"] for item in evidence.facts["matches"]} == {
        "private_key",
        "high_entropy",
    }


def test_read_budget_uses_probe_bytes_without_a_second_read(tmp_path: Path) -> None:
    """Catches a binary probe that rereads content or exceeds the real byte budget."""
    class CountingStream(io.BytesIO):
        def __init__(self, payload: bytes) -> None:
            super().__init__(payload)
            self.read_bytes = 0

        def read(self, size: int = -1) -> bytes:
            result = super().read(size)
            self.read_bytes += len(result)
            return result

        def fileno(self) -> int:
            return 17

    target = tmp_path / "config.txt"
    target.write_text("placeholder", encoding="utf-8")
    payload = CANARY.encode()
    stream = CountingStream(payload)
    opened = SafeRegularFile(stream, len(payload))

    with (
        patch("repoproof.collectors.secrets.open_regular_file", return_value=opened),
        patch(
            "repoproof.collectors.secrets.os.fstat",
            return_value=SimpleNamespace(st_size=len(payload)),
        ),
    ):
        evidence = _collect(tmp_path, max_read_bytes=len(payload))

    assert stream.read_bytes <= len(payload)
    assert [item["category"] for item in evidence.facts["matches"]] == ["token"]


def test_high_entropy_allowlist_uses_only_rules_whose_threshold_triggered(tmp_path: Path) -> None:
    """Catches allowlist metadata that credits a stricter non-triggered entropy rule."""
    value = "abcdefghijklmnopqrstuvwx0123456789ABCDEFGH"
    target = tmp_path / "config.txt"
    target.write_text(f"password={value}\n", encoding="utf-8")
    fingerprint = hashlib.sha256(value.encode()).hexdigest()[:8]
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.low\n"
        "    path: config.txt\n"
        f"    fingerprint: {fingerprint}\n"
        "  - rule_id: security.high\n"
        "    path: config.txt\n"
        f"    fingerprint: {fingerprint}\n",
        encoding="utf-8",
    )
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": "entropy-policy",
            "description": "entropy test",
            "rules": [
                {
                    "id": "security.low",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["high_entropy"], "entropy_threshold": 3.0},
                    "remediation": "remove it",
                },
                {
                    "id": "security.high",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["high_entropy"], "entropy_threshold": 8.0},
                    "remediation": "remove it",
                },
            ],
        }
    )

    evidence = SecretCollector().collect(AuditContext(tmp_path, offline=True), profile)[0]
    match = evidence.facts["matches"][0]

    assert match["category"] == "high_entropy"
    assert match["allowlisted_for"] == ("security.low",)
