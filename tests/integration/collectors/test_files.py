import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import FileCollector, _is_link_or_junction
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile


def test_inventory_respects_git_and_repoproof_ignore(tmp_path: Path) -> None:
    """Catches enumeration that includes paths excluded by either ignore file."""
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (tmp_path / ".repoproofignore").write_text("private/**\n", encoding="utf-8")
    (tmp_path / "kept.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("no", encoding="utf-8")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "hidden.txt").write_text("no", encoding="utf-8")

    evidence = FileCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )[0]

    assert evidence.facts["paths"] == (".gitignore", ".repoproofignore", "kept.txt")


def test_external_symlink_is_not_read(tmp_path: Path) -> None:
    """Catches inventory code that traverses or reports files behind external links."""
    outside = tmp_path / "outside.txt"
    outside.write_text("canary", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")

    evidence = FileCollector().collect(AuditContext(root, offline=True), load_profile("ai4se-b"))[0]

    assert "link.txt" not in evidence.facts["paths"]
    assert "canary" not in repr(evidence)


def test_external_ignore_symlink_cannot_control_inventory(tmp_path: Path) -> None:
    """Catches ignore loading that reads exclusion rules from outside the repository."""
    outside = tmp_path / "outside-ignore"
    outside.write_text("kept.txt\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "kept.txt").write_text("ok", encoding="utf-8")
    ignore_link = root / ".gitignore"
    try:
        ignore_link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")

    evidence = FileCollector().collect(AuditContext(root, offline=True), load_profile("ai4se-b"))[0]

    assert evidence.facts["paths"] == ("kept.txt",)


def test_ignore_file_respects_context_max_read_bytes(tmp_path: Path) -> None:
    """Catches ignore loading that bypasses the context read-size limit."""
    (tmp_path / ".gitignore").write_text("kept.txt\n", encoding="utf-8")
    (tmp_path / "kept.txt").write_text("ok", encoding="utf-8")

    evidence = FileCollector().collect(
        AuditContext(tmp_path, offline=True, max_read_bytes=1), load_profile("ai4se-b")
    )[0]

    assert evidence.facts["paths"] == (".gitignore", "kept.txt")


def test_expired_context_does_not_read_ignore_files(tmp_path: Path) -> None:
    """Catches timeout setup that starts only after ignore-file I/O has occurred."""
    (tmp_path / ".gitignore").write_text("kept.txt\n", encoding="utf-8")
    profile = load_profile("ai4se-b")

    with patch.object(Path, "read_text", side_effect=AssertionError("ignore file was read")):
        with pytest.raises(RuntimeFailure, match="timed out"):
            FileCollector().collect(
                AuditContext(tmp_path, offline=True, timeout_seconds=-1), profile
            )


def test_ignore_file_io_error_fails_closed(tmp_path: Path) -> None:
    """Catches unreadable ignore files that are silently treated as no ignore rules."""
    (tmp_path / ".gitignore").write_text("kept.txt\n", encoding="utf-8")
    profile = load_profile("ai4se-b")

    with patch.object(
        Path,
        "read_text",
        side_effect=PermissionError("C:/outside/private-ignore-file"),
    ):
        with pytest.raises(RuntimeFailure, match="Unable to read repository ignore file"):
            FileCollector().collect(AuditContext(tmp_path, offline=True), profile)


@pytest.mark.skipif(
    not hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"),
    reason="Windows reparse-point attributes are unavailable",
)
def test_reparse_point_attribute_is_rejected_beyond_junctions(tmp_path: Path) -> None:
    """Catches reparse detection that recognizes only symlinks and junctions."""
    candidate = tmp_path / "reparse-like.txt"
    candidate.write_text("safe", encoding="utf-8")
    reparse_stat = SimpleNamespace(
        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
        st_mode=stat.S_IFREG,
    )

    with patch.object(Path, "lstat", return_value=reparse_stat):
        assert _is_link_or_junction(candidate)


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows filesystem feature")
def test_external_junction_is_not_inventoried(tmp_path: Path) -> None:
    """Catches inventory code that reports files reachable through an external junction."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.txt").write_text("canary", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    junction = root / "linked"
    try:
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        pytest.skip("junction creation unavailable")
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")

    evidence = FileCollector().collect(AuditContext(root, offline=True), load_profile("ai4se-b"))[0]

    assert "linked/canary.txt" not in evidence.facts["paths"]
    assert "canary" not in repr(evidence)


def test_candidate_limit_fails_closed(tmp_path: Path) -> None:
    """Catches enumeration that continues after the configured candidate limit."""
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="candidate file limit"):
        FileCollector().collect(
            AuditContext(tmp_path, offline=True, max_files=2), load_profile("ai4se-b")
        )


def test_enumeration_timeout_fails_closed(tmp_path: Path) -> None:
    """Catches enumeration that ignores the configured wall-clock time bound."""
    (tmp_path / "kept.txt").write_text("x", encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="timed out"):
        FileCollector().collect(
            AuditContext(tmp_path, offline=True, timeout_seconds=0.0), load_profile("ai4se-b")
        )


def test_directory_scan_error_fails_closed_without_leaking_os_detail(tmp_path: Path) -> None:
    """Catches scan errors that are silently discarded as available empty evidence."""
    profile = load_profile("ai4se-b")

    with patch(
        "repoproof.collectors.files.os.scandir",
        side_effect=PermissionError("C:/outside/private-repository"),
    ):
        with pytest.raises(RuntimeFailure, match="Unable to enumerate repository") as error:
            FileCollector().collect(AuditContext(tmp_path, offline=True), profile)

    assert "private-repository" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
