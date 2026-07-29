from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from pytest import MonkeyPatch

from repoproof.collectors.git import GitRunner


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
