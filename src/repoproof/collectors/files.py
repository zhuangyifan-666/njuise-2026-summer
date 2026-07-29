import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

import pathspec

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import Profile

DEFAULT_IGNORES = (".git/", ".venv/", "build/", "dist/", "__pycache__/")


@dataclass(frozen=True, slots=True)
class RepositoryFile:
    """A checked regular file yielded by the bounded repository traversal."""

    relative: str
    path: Path
    size: int


def _resolves_under_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _is_link_or_junction(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    is_reparse_point = bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return path.is_symlink() or os.path.isjunction(path) or is_reparse_point


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("Repository enumeration timed out.", "Reduce scope or ignored paths.")


def _ignore_spec(root: Path, max_read_bytes: int, deadline: float) -> pathspec.PathSpec:
    lines = list(DEFAULT_IGNORES)
    for name in (".gitignore", ".repoproofignore"):
        _raise_if_timed_out(deadline)
        path = root / name
        failure: RuntimeFailure | None = None
        try:
            if _is_link_or_junction(path) or not _resolves_under_root(root, path):
                continue
            if path.is_file() and path.stat().st_size <= max_read_bytes:
                lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
                _raise_if_timed_out(deadline)
        except OSError:
            failure = RuntimeFailure(
                "Unable to read repository ignore file.",
                "Check repository readability or remove the ignore file.",
            )
        if failure is not None:
            raise failure
    _raise_if_timed_out(deadline)
    ignore_spec = pathspec.PathSpec.from_lines("gitwildmatch", lines)
    _raise_if_timed_out(deadline)
    return ignore_spec


class FileCollector:
    name = "files"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        files = repository_files(context)
        ordered = tuple(file.relative for file in files)
        sizes = {file.relative: file.size for file in files}
        total = sum(file.size for file in files)
        return (
            Evidence(
                id="files.inventory",
                kind="file_inventory",
                subject=".",
                state=EvidenceState.AVAILABLE,
                facts={
                    "paths": ordered,
                    "sizes": {path: sizes[path] for path in ordered},
                    "total_bytes": total,
                },
                provenance=collector_provenance(context, self.name),
            ),
        )


def repository_files(
    context: AuditContext, *, deadline: float | None = None
) -> tuple[RepositoryFile, ...]:
    """Return checked, ignore-aware regular files in deterministic repository order."""
    active_deadline = (
        deadline if deadline is not None else time.monotonic() + context.timeout_seconds
    )
    _raise_if_timed_out(active_deadline)
    try:
        root = context.root.resolve(strict=True)
    except OSError:
        raise RuntimeFailure(
            "Unable to enumerate repository.", "Check repository readability or reduce scope."
        ) from None
    _raise_if_timed_out(active_deadline)
    ignores = _ignore_spec(root, context.max_read_bytes, active_deadline)
    files: list[RepositoryFile] = []
    total = 0
    directories = [root]
    scan_failed = False
    while directories:
        _raise_if_timed_out(active_deadline)
        directory = directories.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    _raise_if_timed_out(active_deadline)
                    candidate = Path(entry.path)
                    relative = candidate.relative_to(root).as_posix()
                    if entry.is_dir(follow_symlinks=False):
                        if (
                            _is_link_or_junction(candidate)
                            or ignores.match_file(f"{relative}/")
                            or not _resolves_under_root(root, candidate)
                        ):
                            continue
                        directories.append(candidate)
                        continue
                    if (
                        ignores.match_file(relative)
                        or not entry.is_file(follow_symlinks=False)
                        or _is_link_or_junction(candidate)
                        or not _resolves_under_root(root, candidate)
                    ):
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                    files.append(RepositoryFile(relative, candidate, size))
                    total += size
                    if len(files) > context.max_files:
                        raise RuntimeFailure(
                            "Repository exceeds candidate file limit.",
                            "Reduce scope or ignored paths.",
                        )
                    if total > context.max_total_bytes:
                        raise RuntimeFailure(
                            "Repository exceeds total byte limit.",
                            "Reduce scope or ignored paths.",
                        )
        except RuntimeFailure:
            raise
        except OSError:
            scan_failed = True
            break
    if scan_failed:
        raise RuntimeFailure(
            "Unable to enumerate repository.", "Check repository readability or reduce scope."
        )
    return tuple(sorted(files, key=lambda file: file.relative))
