import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from repoproof.errors import UsageFailure


class SafeOpenFailure(Exception):
    """A path/handle safety failure with no repository content attached."""


@dataclass(slots=True)
class SafeRegularFile:
    stream: BinaryIO
    size: int

    def close(self) -> None:
        self.stream.close()


def _checked_relative_parts(relative: str) -> tuple[str, ...]:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise SafeOpenFailure
    return candidate.parts


def _open_regular_posix(root: Path, parts: tuple[str, ...]) -> SafeRegularFile:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise SafeOpenFailure
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    root_fd = os.open(root, directory_flags)
    opened_fds = [root_fd]
    try:
        for part in parts[:-1]:
            fd = os.open(part, directory_flags, dir_fd=opened_fds[-1])
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                os.close(fd)
                raise SafeOpenFailure
            opened_fds.append(fd)
        final_fd = os.open(parts[-1], os.O_RDONLY | no_follow, dir_fd=opened_fds[-1])
        file_stat = os.fstat(final_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(final_fd)
            raise SafeOpenFailure
        stream = os.fdopen(final_fd, "rb", closefd=True)
        return SafeRegularFile(stream, file_stat.st_size)
    except OSError as exc:
        raise SafeOpenFailure from exc
    finally:
        for fd in reversed(opened_fds):
            os.close(fd)


def _open_regular_windows(root: Path, relative: str) -> SafeRegularFile:
    """Open the final component itself and validate its opened-handle target.

    FILE_FLAG_OPEN_REPARSE_POINT prevents following a final replaced link. Parent
    components are validated both before opening and by the final handle path;
    no content is read before the containment decision.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    candidate = root.joinpath(*_checked_relative_parts(relative))
    current = root
    for part in _checked_relative_parts(relative):
        current = current / part
        try:
            attributes = current.lstat().st_file_attributes
        except OSError as exc:
            raise SafeOpenFailure from exc
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SafeOpenFailure
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(candidate),
        0x80000000,
        0x00000001,
        None,
        3,
        0x00200000,
        None,
    )
    invalid_handle = wintypes.HANDLE(-1).value
    if handle == invalid_handle:
        raise SafeOpenFailure
    descriptor: int | None = None
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SafeOpenFailure
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise SafeOpenFailure
        final_name = buffer.value.removeprefix("\\\\?\\")
        try:
            Path(final_name).resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise SafeOpenFailure from exc
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        return SafeRegularFile(stream, file_stat.st_size)
    except OSError as exc:
        raise SafeOpenFailure from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def open_regular_file(root: Path, relative: str) -> SafeRegularFile:
    """Atomically open an in-root regular file without trusting its prior path stat."""
    parts = _checked_relative_parts(relative)
    if os.name == "nt":
        return _open_regular_windows(root, relative)
    return _open_regular_posix(root, parts)


def resolve_under_root(root: Path, candidate: str) -> Path:
    relative = Path(candidate)
    if relative.is_absolute():
        raise UsageFailure("Profile paths must be relative.", "Use a repository-relative path.")
    if ".." in relative.parts:
        raise UsageFailure(
            "Path resolves outside repository.", "Remove traversal or external links."
        )
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / relative).resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise UsageFailure(
            "Path resolves outside repository.", "Remove traversal or external links."
        ) from exc
    return resolved


def short_fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    redacted = text
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    return redacted
