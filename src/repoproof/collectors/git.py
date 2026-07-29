import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile

MAX_GIT_OUTPUT_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_CLEANUP_TIMEOUT_SECONDS = 0.1


def _read_bounded_output(
    stream: IO[bytes], maximum: int, output: bytearray, read_failed: list[bool]
) -> None:
    try:
        while chunk := stream.read(_READ_CHUNK_BYTES):
            remaining = maximum - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
    except Exception:
        read_failed[0] = True


def _remaining_seconds(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.0)


def _ignore_cleanup_failure(operation: Callable[[], object]) -> None:
    try:
        operation()
    except Exception:
        return


def _bounded_wait(process: subprocess.Popen[bytes], deadline: float) -> None:
    try:
        process.wait(timeout=_remaining_seconds(deadline))
    except Exception:
        return


def _bounded_join(reader: threading.Thread, deadline: float) -> None:
    try:
        reader.join(timeout=_remaining_seconds(deadline))
    except Exception:
        return


def _cleanup_process(
    process: subprocess.Popen[bytes], stream: IO[bytes] | None, reader: threading.Thread | None
) -> None:
    deadline = time.monotonic() + _CLEANUP_TIMEOUT_SECONDS
    if stream is not None:
        _ignore_cleanup_failure(stream.close)
    if process.returncode is None:
        _ignore_cleanup_failure(process.terminate)
        _bounded_wait(process, deadline)
    if process.returncode is None:
        _ignore_cleanup_failure(process.kill)
        _bounded_wait(process, deadline)
    if reader is not None:
        _bounded_join(reader, deadline)


@dataclass(frozen=True, slots=True)
class GitRunner:
    executable: str = "git"

    def run(self, root: Path, args: tuple[str, ...], timeout: float, max_output: int) -> str:
        if max_output < 0:
            raise ValueError("max_output must not be negative")
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(
            [self.executable, *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        stream = process.stdout
        if stream is None:
            _cleanup_process(process, None, None)
            raise RuntimeError("git command unavailable")
        output = bytearray()
        read_failed = [False]
        reader = threading.Thread(
            target=_read_bounded_output,
            args=(stream, max_output, output, read_failed),
            daemon=True,
        )
        reader.start()
        try:
            process.wait(timeout=max(deadline - time.monotonic(), 0.0))
            reader.join(timeout=max(deadline - time.monotonic(), 0.0))
            if reader.is_alive():
                raise subprocess.TimeoutExpired([self.executable, *args], timeout)
            if read_failed[0] or process.returncode != 0:
                raise RuntimeError("git command unavailable")
            return bytes(output).decode("utf-8", errors="replace").strip()
        finally:
            if process.returncode is None or reader.is_alive():
                _cleanup_process(process, stream, reader)


class _GitCommandRunner(Protocol):
    def run(self, root: Path, args: tuple[str, ...], timeout: float, max_output: int) -> str: ...


class GitCollector:
    name = "git"

    def __init__(self, runner: _GitCommandRunner | None = None) -> None:
        self.runner = runner or GitRunner()

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        del profile
        deadline = time.monotonic() + context.timeout_seconds
        max_output = min(context.max_read_bytes, MAX_GIT_OUTPUT_BYTES)

        def run(args: tuple[str, ...]) -> str:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or max_output <= 0:
                raise subprocess.TimeoutExpired(["git", *args], max(remaining, 0.0))
            return self.runner.run(context.root, args, remaining, max_output)

        try:
            inside = run(("rev-parse", "--is-inside-work-tree")) == "true"
            current = run(("branch", "--show-current"))
            commits = int(run(("rev-list", "--count", "HEAD")))
            branches = tuple(
                sorted(
                    filter(
                        None,
                        run(
                            (
                                "for-each-ref",
                                "--format=%(refname:short)",
                                "refs/heads",
                            )
                        ).splitlines(),
                    )
                )
            )
            merges = int(run(("rev-list", "--count", "--merges", "HEAD")))
            facts: dict[str, object] = {
                "is_repository": inside,
                "current_branch": current,
                "default_branch": "main"
                if "main" in branches
                else "master"
                if "master" in branches
                else "",
                "commit_count": commits,
                "branches": branches,
                "merge_count": merges,
            }
            state = EvidenceState.AVAILABLE
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError):
            facts = {"reason": "git_unavailable_or_not_repository"}
            state = EvidenceState.UNAVAILABLE
        return (
            Evidence(
                "git:history",
                "git_history",
                ".",
                state,
                facts,
                collector_provenance(context, self.name),
            ),
        )
