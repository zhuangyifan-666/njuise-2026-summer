from pathlib import Path

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.markdown import MarkdownCollector
from repoproof.domain import EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile


def test_atx_setext_and_completed_commit_evidence(tmp_path: Path) -> None:
    """Catches collectors that miss Markdown heading styles or checklist hashes."""
    (tmp_path / "README.md").write_text("# Overview\n\nInstallation\n====\n", encoding="utf-8")
    (tmp_path / "PLAN.md").write_text(
        "- [x] parser (`1a2b3c4`)\n"
        "- [x] malformed 1a2b3c4z\n"
        "- [x] underscore 1a2b3c4_suffix\n"
        "- [x] unicode 1a2b3c4汉\n"
        "- [x] too-short abcdef\n"
        "- [x] too-long 12345678901234567890123456789012345678901\n"
        "- [ ] release\n",
        encoding="utf-8",
    )

    evidence = MarkdownCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )
    by_subject = {item.subject: item for item in evidence}

    assert by_subject["README.md"].facts["headings"] == ("overview", "installation")
    assert by_subject["PLAN.md"].facts["completed_items"] == (
        {"line": 1, "has_commit": True},
        {"line": 2, "has_commit": False},
        {"line": 3, "has_commit": False},
        {"line": 4, "has_commit": False},
        {"line": 5, "has_commit": False},
        {"line": 6, "has_commit": False},
    )


def test_invalid_utf8_is_limited_without_replacement_decoding(tmp_path: Path) -> None:
    """Catches evidence that silently substitutes invalid UTF-8 input."""
    (tmp_path / "README.md").write_bytes(b"# valid\n\xff")

    evidence = MarkdownCollector().collect(
        AuditContext(tmp_path, offline=True), load_profile("ai4se-b")
    )
    by_subject = {item.subject: item for item in evidence}

    assert by_subject["README.md"].state is EvidenceState.LIMITED
    assert by_subject["README.md"].facts == {"reason": "invalid_utf8"}


def test_markdown_larger_than_read_limit_is_limited(tmp_path: Path) -> None:
    """Catches Markdown parsing that bypasses the configured per-file read limit."""
    (tmp_path / "README.md").write_text("# Overview\n", encoding="utf-8")

    evidence = MarkdownCollector().collect(
        AuditContext(tmp_path, offline=True, max_read_bytes=1), load_profile("ai4se-b")
    )
    by_subject = {item.subject: item for item in evidence}

    assert by_subject["README.md"].state is EvidenceState.LIMITED
    assert by_subject["README.md"].facts == {"reason": "file_too_large"}


def test_expired_context_fails_before_markdown_file_io(tmp_path: Path) -> None:
    """Catches Markdown collection that ignores the context wall-clock deadline."""
    with pytest.raises(RuntimeFailure, match="timed out"):
        MarkdownCollector().collect(
            AuditContext(tmp_path, offline=True, timeout_seconds=-1), load_profile("ai4se-b")
        )
