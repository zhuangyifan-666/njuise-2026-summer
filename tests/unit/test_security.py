import os
import subprocess
from pathlib import Path

import pytest

import repoproof.security as security
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


@pytest.mark.skipif(os.name != "nt", reason="Windows native handles are required")
def test_windows_final_open_is_parent_relative_and_rejects_replacement_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches a Windows walk that reopens a child through a reconstructed absolute path."""
    root = tmp_path / "repo"
    parent = root / "parent"
    parent.mkdir(parents=True)
    candidate = parent / "candidate.txt"
    candidate.write_text("original", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.txt").write_text("replacement-junction-canary", encoding="utf-8")

    relative_open = security._open_windows_relative
    calls: list[tuple[int, str, bool]] = []
    directory_handles: dict[str, int] = {}
    mutation_succeeded = False

    def racing_open(parent_handle: int, component: str, *, directory: bool) -> int:
        nonlocal mutation_succeeded
        assert Path(component).parts == (component,)
        assert not Path(component).is_absolute()
        calls.append((parent_handle, component, directory))
        if component == "candidate.txt":
            candidate.unlink()
            result = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(candidate), str(outside)],
                capture_output=True,
                check=False,
                text=True,
            )
            if result.returncode != 0:
                pytest.skip("junction creation unavailable")
            mutation_succeeded = True
        handle = relative_open(parent_handle, component, directory=directory)
        if directory:
            directory_handles[component] = handle
        return handle

    monkeypatch.setattr(security, "_open_windows_relative", racing_open)
    try:
        with pytest.raises(SafeOpenFailure):
            open_regular_file(root, "parent/candidate.txt")
    finally:
        if os.path.isjunction(candidate):
            candidate.rmdir()

    assert mutation_succeeded
    assert [(component, directory) for _, component, directory in calls] == [
        ("parent", True),
        ("candidate.txt", False),
    ]
    assert calls[-1][0] == directory_handles["parent"]
