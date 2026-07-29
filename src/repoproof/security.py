import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from repoproof.errors import UsageFailure


class SafeOpenFailure(Exception):
    """A path/handle safety failure with no repository content attached."""

    def __init__(self, reason: str = "unsafe") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class SafeRegularFile:
    stream: BinaryIO
    size: int

    def close(self) -> None:
        self.stream.close()


def _checked_relative_parts(relative: str) -> tuple[str, ...]:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise SafeOpenFailure("unsafe")
    return candidate.parts


def _open_regular_posix(root: Path, parts: tuple[str, ...]) -> SafeRegularFile:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise SafeOpenFailure
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    try:
        root_fd = os.open(root, directory_flags)
    except FileNotFoundError as exc:
        raise SafeOpenFailure("missing") from exc
    except OSError as exc:
        raise SafeOpenFailure("operational") from exc
    opened_fds = [root_fd]
    try:
        for part in parts[:-1]:
            fd = os.open(part, directory_flags, dir_fd=opened_fds[-1])
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                os.close(fd)
                raise SafeOpenFailure("unsafe")
            opened_fds.append(fd)
        final_fd = os.open(parts[-1], os.O_RDONLY | no_follow, dir_fd=opened_fds[-1])
        file_stat = os.fstat(final_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(final_fd)
            raise SafeOpenFailure("unsafe")
        stream = os.fdopen(final_fd, "rb", closefd=True)
        return SafeRegularFile(stream, file_stat.st_size)
    except FileNotFoundError as exc:
        raise SafeOpenFailure("missing") from exc
    except OSError as exc:
        raise SafeOpenFailure("operational") from exc
    finally:
        for fd in reversed(opened_fds):
            os.close(fd)


def _open_regular_windows(root: Path, relative: str) -> SafeRegularFile:
    """Walk Windows components with pinned no-reparse handles before reading."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    parts = _checked_relative_parts(relative)
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
    invalid_handle = wintypes.HANDLE(-1).value
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_info = ctypes.windll.kernel32.GetFileInformationByHandleEx
    get_info.argtypes = [wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD]
    get_info.restype = wintypes.BOOL

    class AttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    def open_component(path: Path, final: bool) -> int:
        access = 0x80000000 if final else 0x00000080
        flags = 0x00200000 | (0 if final else 0x02000000)
        handle = create_file(str(path), access, 0x00000003, None, 3, flags, None)
        if handle == invalid_handle:
            error = ctypes.windll.kernel32.GetLastError()
            if error in {2, 3}:
                raise SafeOpenFailure("missing")
            raise SafeOpenFailure("operational")
        info = AttributeTagInfo()
        if not get_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            close_handle(handle)
            raise SafeOpenFailure("operational")
        if info.attributes & 0x00000400 or info.tag or (final and info.attributes & 0x00000010):
            close_handle(handle)
            raise SafeOpenFailure("unsafe")
        return int(handle)

    handles: list[int] = []
    descriptor: int | None = None
    final_handle: int | None = None
    try:
        current = root
        handles.append(open_component(current, False))
        for part in parts[:-1]:
            current = current / part
            handles.append(open_component(current, False))
        final_handle = open_component(current / parts[-1], True)
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetFinalPathNameByHandleW(
            final_handle, buffer, len(buffer), 0
        )
        if not length or length >= len(buffer):
            raise SafeOpenFailure("operational")
        final_name = buffer.value.removeprefix("\\\\?\\")
        try:
            Path(final_name).resolve(strict=True).relative_to(root.resolve(strict=True))
        except ValueError:
            raise SafeOpenFailure("unsafe") from None
        except OSError:
            raise SafeOpenFailure("operational") from None
        descriptor = msvcrt.open_osfhandle(final_handle, os.O_RDONLY | os.O_BINARY)
        final_handle = None
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SafeOpenFailure("unsafe")
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        return SafeRegularFile(stream, file_stat.st_size)
    except SafeOpenFailure:
        raise
    except OSError:
        raise SafeOpenFailure("operational") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if final_handle is not None:
            close_handle(final_handle)
        for handle in reversed(handles):
            close_handle(handle)


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
