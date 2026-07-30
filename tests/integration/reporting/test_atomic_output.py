from pathlib import Path
from unittest.mock import patch

import pytest

from repoproof.reporting.output import atomic_write_text


class _FailingHandle:
    def __init__(
        self,
        descriptor: int,
        *,
        fail_write: bool = False,
        fail_flush: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.descriptor = descriptor
        self.fail_write = fail_write
        self.fail_flush = fail_flush
        self.fail_close = fail_close
        self.closed = False

    def write(self, content: str) -> int:
        if self.fail_write:
            raise KeyboardInterrupt("write interrupted")
        return len(content)

    def flush(self) -> None:
        if self.fail_flush:
            raise OSError("flush blocked")
        return None

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            import os

            os.close(self.descriptor)
        if self.fail_close:
            raise OSError("close blocked")

    def __enter__(self) -> "_FailingHandle":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _ReusingCloseHandle:
    def __init__(self, descriptor: int, replacement: Path) -> None:
        self.descriptor = descriptor
        self.replacement = replacement
        self.reused_descriptor: int | None = None

    def write(self, content: str) -> int:
        return len(content)

    def flush(self) -> None:
        return None

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        import os

        os.close(self.descriptor)
        self.reused_descriptor = os.open(self.replacement, os.O_RDWR)
        raise OSError("close hook")


def test_atomic_write_uses_utf8_lf_and_creates_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "report.json"

    atomic_write_text(target, "first\r\nsecond\rthird")

    assert target.read_bytes() == b"first\nsecond\nthird"
    assert list(target.parent.glob(".report.json.*.tmp")) == []


def test_failed_replace_leaves_existing_report_intact_and_cleans_temp(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("old", encoding="utf-8")

    with patch("repoproof.reporting.output.os.replace", side_effect=OSError("blocked")):
        with pytest.raises(OSError, match="blocked"):
            atomic_write_text(report, "new")

    assert report.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_interrupted_write_cleans_temp_and_does_not_create_target(tmp_path: Path) -> None:
    target = tmp_path / "report.html"

    with patch("repoproof.reporting.output.os.fsync", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            atomic_write_text(target, "new")

    assert not target.exists()
    assert list(tmp_path.glob(".report.html.*.tmp")) == []


def test_write_failure_keeps_primary_interrupt_when_close_also_fails(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")
    captured: dict[str, int] = {}

    import repoproof.reporting.output as output

    real_mkstemp = output.tempfile.mkstemp

    def record_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        descriptor, path = real_mkstemp(*args, **kwargs)
        captured["descriptor"] = descriptor
        return descriptor, path

    with (
        patch("repoproof.reporting.output.tempfile.mkstemp", side_effect=record_mkstemp),
        patch(
            "repoproof.reporting.output.os.fdopen",
            side_effect=lambda descriptor, *args, **kwargs: _FailingHandle(
                descriptor, fail_write=True, fail_close=True
            ),
        ),
    ):
        with pytest.raises(KeyboardInterrupt, match="write interrupted"):
            atomic_write_text(target, "secret content must not leak")

    with pytest.raises(OSError):
        import os

        os.fstat(captured["descriptor"])
    assert target.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_fdopen_failure_releases_raw_descriptor_and_temp(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    captured: dict[str, int] = {}

    import repoproof.reporting.output as output

    real_mkstemp = output.tempfile.mkstemp

    def record_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        descriptor, path = real_mkstemp(*args, **kwargs)
        captured["descriptor"] = descriptor
        return descriptor, path

    with (
        patch("repoproof.reporting.output.tempfile.mkstemp", side_effect=record_mkstemp),
        patch("repoproof.reporting.output.os.fdopen", side_effect=OSError("fdopen blocked")),
    ):
        with pytest.raises(OSError, match="fdopen blocked"):
            atomic_write_text(target, "secret content must not leak")

    with pytest.raises(OSError):
        import os

        os.fstat(captured["descriptor"])
    assert not target.exists()
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_flush_failure_preserves_its_error_and_cleans_temp(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")

    with patch(
        "repoproof.reporting.output.os.fdopen",
        side_effect=lambda descriptor, *args, **kwargs: _FailingHandle(
            descriptor, fail_flush=True
        ),
    ):
        with pytest.raises(OSError, match="flush blocked"):
            atomic_write_text(target, "secret content must not leak")

    assert target.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_close_hook_fd_reuse_does_not_close_unrelated_reopened_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("still open", encoding="utf-8")
    captured: dict[str, _ReusingCloseHandle] = {}

    def reusing_handle(descriptor: int, *args: object, **kwargs: object) -> _ReusingCloseHandle:
        handle = _ReusingCloseHandle(descriptor, replacement)
        captured["handle"] = handle
        return handle

    with patch("repoproof.reporting.output.os.fdopen", side_effect=reusing_handle):
        with pytest.raises(OSError, match="close hook"):
            atomic_write_text(target, "new")

    descriptor = captured["handle"].reused_descriptor
    assert descriptor is not None
    try:
        import os

        assert os.fstat(descriptor).st_size == len("still open")
    finally:
        import os

        try:
            os.close(descriptor)
        except OSError:
            pass
    assert not target.exists()
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_initial_descriptor_identity_interrupt_propagates_and_keeps_target(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("old", encoding="utf-8")

    with (
        patch("repoproof.reporting.output.os.fstat", side_effect=KeyboardInterrupt("stop")),
        patch("repoproof.reporting.output.os.replace") as replace,
    ):
        with pytest.raises(KeyboardInterrupt, match="stop"):
            atomic_write_text(target, "new")

    assert target.read_text(encoding="utf-8") == "old"
    replace.assert_not_called()
    assert list(tmp_path.glob(".report.json.*.tmp")) == []
