import subprocess
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pytest import MonkeyPatch

from repoproof.collectors.base import AuditContext
from repoproof.collectors.git import GitCollector, GitRunner, repository_slug
from repoproof.domain import EvidenceState
from repoproof.profile.loader import load_profile


def test_repository_slug_accepts_only_safe_github_origins() -> None:
    """Catches attacker-controlled or non-GitHub origins entering API paths."""
    assert repository_slug("https://github.com/owner/repo.git") == "owner/repo"
    assert repository_slug("git@github.com:owner/repo") == "owner/repo"
    assert repository_slug("https://github.com.evil.invalid/owner/repo.git") is None


class _CompletedProcess:
    def __init__(self, output: bytes) -> None:
        self.returncode = 0
        self.stdout = BytesIO(output)

    def wait(self, timeout: float) -> int:
        del timeout
        return self.returncode


def test_git_runner_uses_argument_array_and_never_shell(tmp_path: Path) -> None:
    """Catches Git execution that builds a shell command from repository data."""
    with patch(
        "repoproof.collectors.git.subprocess.Popen",
        return_value=_CompletedProcess(b"main\n"),
    ) as popen:
        result = GitRunner().run(tmp_path, ("branch", "--show-current"), 10.0, 1024)

    assert result == "main"
    args, kwargs = popen.call_args
    assert args[0] == ["git", "branch", "--show-current"]
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == tmp_path


def test_git_runner_retains_only_the_configured_output_limit(tmp_path: Path) -> None:
    """Catches a runner that buffers unlimited Git output before truncating it."""
    with patch(
        "repoproof.collectors.git.subprocess.Popen",
        return_value=_CompletedProcess(b"abcdefgh"),
    ):
        result = GitRunner().run(tmp_path, ("branch", "--show-current"), 10.0, 4)

    assert result == "abcd"


class _ImmediateThread:
    join_timeouts: list[float | None] = []

    def __init__(self, **kwargs: object) -> None:
        del kwargs

    def start(self) -> None:
        return None

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)

    def is_alive(self) -> bool:
        return False


def test_git_runner_shares_its_deadline_with_output_draining(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """Catches a successful process getting a second full timeout to drain stdout."""
    _ImmediateThread.join_timeouts.clear()
    moments = iter((10.0, 10.0, 12.0))
    monkeypatch.setattr("repoproof.collectors.git.time.monotonic", lambda: next(moments))
    with patch(
        "repoproof.collectors.git.subprocess.Popen",
        return_value=_CompletedProcess(b"main\n"),
    ):
        with patch("repoproof.collectors.git.threading.Thread", _ImmediateThread):
            GitRunner().run(tmp_path, ("branch", "--show-current"), 5.0, 1024)

    assert _ImmediateThread.join_timeouts == [3.0]


class _CleanupFailureStream:
    def close(self) -> None:
        raise OSError("private pipe cleanup failure")


class _CleanupFailureProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.stdout = _CleanupFailureStream()
        self.wait_timeouts: list[float] = []
        self.terminate_calls = 0
        self.kill_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        if timeout is None:
            raise AssertionError("unbounded wait")
        self.wait_timeouts.append(timeout)
        raise subprocess.TimeoutExpired("git", timeout)

    def terminate(self) -> None:
        self.terminate_calls += 1
        raise OSError("private terminate failure")

    def kill(self) -> None:
        self.kill_calls += 1
        raise OSError("private kill failure")


class _StuckReader:
    instances: list["_StuckReader"] = []

    def __init__(self, **kwargs: object) -> None:
        del kwargs
        self.join_timeouts: list[float | None] = []
        self.instances.append(self)

    def start(self) -> None:
        return None

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)

    def is_alive(self) -> bool:
        return True


def test_git_runner_timeout_cleanup_stays_bounded_when_cleanup_operations_fail(
    tmp_path: Path
) -> None:
    """Catches timeout cleanup that blocks or leaks failures from process and pipe cleanup."""
    process = _CleanupFailureProcess()
    _StuckReader.instances.clear()
    with patch("repoproof.collectors.git.subprocess.Popen", return_value=process):
        with patch("repoproof.collectors.git.threading.Thread", _StuckReader):
            with pytest.raises(subprocess.TimeoutExpired) as error:
                GitRunner().run(tmp_path, ("status", "--short"), 0.0, 1024)

    assert "private" not in str(error.value)
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.wait_timeouts
    assert all(0.0 <= timeout <= 1.0 for timeout in process.wait_timeouts)
    assert _StuckReader.instances[0].join_timeouts
    assert all(
        timeout is not None and 0.0 <= timeout <= 1.0
        for timeout in _StuckReader.instances[0].join_timeouts
    )


class _ReadFailureStream:
    def read(self, size: int) -> bytes:
        del size
        raise OSError("private stream failure")

    def close(self) -> None:
        return None


class _ReadFailureProcess:
    def __init__(self) -> None:
        self.returncode = 0
        self.stdout = _ReadFailureStream()

    def wait(self, timeout: float) -> int:
        del timeout
        return self.returncode


def test_git_collector_sanitizes_reader_failures_without_thread_exception_output(
    tmp_path: Path
) -> None:
    """Catches pipe-read failures escaping a worker or returning partial available evidence."""
    exception_hook = Mock()
    with patch(
        "repoproof.collectors.git.subprocess.Popen",
        return_value=_ReadFailureProcess(),
    ):
        with patch("repoproof.collectors.git.threading.excepthook", exception_hook):
            evidence = GitCollector().collect(
                AuditContext(tmp_path, True), load_profile("ai4se-b")
            )[0]

    assert evidence.state is EvidenceState.UNAVAILABLE
    assert evidence.facts == {"reason": "git_unavailable_or_not_repository"}
    assert "private stream failure" not in repr(evidence)
    exception_hook.assert_not_called()


class _CloseContentionProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_timeouts: list[float] = []
        self.stdout = _CloseContentionStream(self)

    def wait(self, timeout: float | None = None) -> int:
        if timeout is None:
            raise AssertionError("unbounded wait")
        self.wait_timeouts.append(timeout)
        raise subprocess.TimeoutExpired("git", timeout)

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1


class _CloseContentionStream:
    def __init__(self, process: _CloseContentionProcess) -> None:
        self.process = process
        self.close_before_termination = False

    def close(self) -> None:
        if self.process.terminate_calls == 0:
            self.close_before_termination = True
            raise AssertionError("close contended with reader-held pipe lock")


def test_git_runner_terminates_before_attempting_a_contended_pipe_close(tmp_path: Path) -> None:
    """Catches cleanup that can block on stdout close before stopping the child process."""
    process = _CloseContentionProcess()
    _StuckReader.instances.clear()
    with patch("repoproof.collectors.git.subprocess.Popen", return_value=process):
        with patch("repoproof.collectors.git.threading.Thread", _StuckReader):
            with pytest.raises(subprocess.TimeoutExpired):
                GitRunner().run(tmp_path, ("status", "--short"), 0.0, 1024)

    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.stdout.close_before_termination is False
    assert all(0.0 <= timeout <= 1.0 for timeout in process.wait_timeouts)


class _StartFailureReader:
    def __init__(self, **kwargs: object) -> None:
        del kwargs

    def start(self) -> None:
        raise RuntimeError("private reader start failure")

    def is_alive(self) -> bool:
        return False

    def join(self, timeout: float | None = None) -> None:
        del timeout


def test_git_collector_cleans_up_when_reader_start_fails(tmp_path: Path) -> None:
    """Catches a thread-start failure that bypasses cleanup after a Git process is created."""
    process = _CloseContentionProcess()
    with patch("repoproof.collectors.git.subprocess.Popen", return_value=process):
        with patch("repoproof.collectors.git.threading.Thread", _StartFailureReader):
            evidence = GitCollector().collect(
                AuditContext(tmp_path, True), load_profile("ai4se-b")
            )[0]

    assert evidence.state is EvidenceState.UNAVAILABLE
    assert evidence.facts == {"reason": "git_unavailable_or_not_repository"}
    assert "private reader start failure" not in repr(evidence)
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert all(0.0 <= timeout <= 1.0 for timeout in process.wait_timeouts)
