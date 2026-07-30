import io
import traceback
from pathlib import Path

import pytest

from repoproof.allowlist import load_secret_allowlist
from repoproof.errors import UsageFailure
from repoproof.security import SafeRegularFile


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


def test_allowlist_failure_traceback_never_retains_untrusted_text(tmp_path: Path) -> None:
    """Catches outer allowlist errors whose frame locals retain parser input."""
    marker = "allowlist-traceback-canary"
    (tmp_path / ".repoproofallowlist.yml").write_text(
        f"schema: 1\nentries: [{{value: {marker}}}]\n", encoding="utf-8"
    )

    with pytest.raises(UsageFailure) as error:
        load_secret_allowlist(tmp_path)

    assert not _traceback_contains(error.value, marker)


def test_allowlist_deep_structure_is_safely_rejected_without_traceback_leak(tmp_path: Path) -> None:
    """Catches parser recursion/depth failures that retain a nested raw document."""
    marker = "nested-allowlist-canary"
    nested = "[" * 80 + marker + "]" * 80
    (tmp_path / ".repoproofallowlist.yml").write_text(
        f"schema: 1\nentries: {nested}\n", encoding="utf-8"
    )

    with pytest.raises(UsageFailure) as error:
        load_secret_allowlist(tmp_path)

    assert not _traceback_contains(error.value, marker)


def test_allowlist_close_failure_cannot_leak_raw_parser_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches a close error replacing the sanitized parser result with raw locals."""
    marker = "close-traceback-canary"
    class BrokenHandle(SafeRegularFile):
        def close(self) -> None:
            raise OSError(marker)

    stream = io.BytesIO(f"schema: 1\nentries: [{{value: {marker}}}]\n".encode())
    handle = BrokenHandle(stream, len(stream.getvalue()))
    monkeypatch.setattr("repoproof.allowlist.open_regular_file", lambda _root, _name: handle)
    with pytest.raises(UsageFailure) as error:
        load_secret_allowlist(tmp_path)

    assert not _traceback_contains(error.value, marker)
