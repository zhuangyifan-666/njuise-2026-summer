import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile

MAX_GIT_OUTPUT_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


def _read_bounded_output(stream: BinaryIO, maximum: int, output: bytearray) -> None:
    while chunk := stream.read(_READ_CHUNK_BYTES):
        remaining = maximum - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])


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
        if process.stdout is None:
            process.kill()
            process.wait()
            raise RuntimeError("git command unavailable")
        output = bytearray()
        reader = threading.Thread(
            target=_read_bounded_output,
            args=(process.stdout, max_output, output),
            daemon=True,
        )
        reader.start()
        try:
            process.wait(timeout=max(deadline - time.monotonic(), 0.0))
            reader.join(timeout=max(deadline - time.monotonic(), 0.0))
            if reader.is_alive():
                raise subprocess.TimeoutExpired([self.executable, *args], timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            reader.join()
            raise
        if process.returncode != 0:
            raise RuntimeError("git command unavailable")
        return bytes(output).decode("utf-8", errors="replace").strip()


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
