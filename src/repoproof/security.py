import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from repoproof.errors import UsageFailure


class SafeOpenFailure(Exception):
    """A path/handle safety failure with no repository content attached."""

    def __init__(self, reason: str = "unsafe") -> None:
        super().__init__(reason)
        self.reason = reason


def _windows_api(module: object, name: str) -> Any:
    """Resolve a Windows-only symbol without requiring it in non-Windows typeshed."""
    return getattr(module, name)


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


def _windows_error_reason(error: int) -> str:
    if error in {2, 3}:
        return "missing"
    if error in {123, 161, 267, 1920, 1921, 4390, 4392, 4393, 4394, 4395}:
        return "unsafe"
    return "operational"


def _raw_windows_open_root(root: Path) -> tuple[str | None, int | None]:
    """Call CreateFileW without allowing native failures into an outward traceback."""
    import ctypes
    from ctypes import wintypes

    owned_handle: int | None = None
    try:
        kernel32 = _windows_api(ctypes, "WinDLL")("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
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
        raw_handle = create_file(
            os.path.abspath(root),
            0x001000A0,
            0x00000003,
            None,
            3,
            0x02200000,
            None,
        )
        if raw_handle == wintypes.HANDLE(-1).value:
            return (_windows_error_reason(_windows_api(ctypes, "get_last_error")()), None)
        if raw_handle is None:
            return ("operational", None)
        owned_handle = int(raw_handle)
        result = owned_handle
        owned_handle = None
        return (None, result)
    except BaseException:
        return ("operational", None)
    finally:
        if owned_handle is not None:
            _close_windows_handle(owned_handle)


def _raw_windows_open_relative(
    parent_handle: int, component: str, *, directory: bool
) -> tuple[str | None, int | None]:
    """Call NtOpenFile relative to a directory handle and contain native failures."""
    import ctypes
    from ctypes import wintypes

    owned_handle: int | None = None
    name_buffer: object | None = None
    object_name: object | None = None
    object_attributes: object | None = None
    io_status: object | None = None
    try:
        class UnicodeString(ctypes.Structure):
            _fields_ = [
                ("length", wintypes.USHORT),
                ("maximum_length", wintypes.USHORT),
                ("buffer", wintypes.LPWSTR),
            ]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [
                ("length", wintypes.ULONG),
                ("root_directory", wintypes.HANDLE),
                ("object_name", ctypes.POINTER(UnicodeString)),
                ("attributes", wintypes.ULONG),
                ("security_descriptor", ctypes.c_void_p),
                ("security_quality_of_service", ctypes.c_void_p),
            ]

        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("status_or_pointer", ctypes.c_void_p), ("information", ctypes.c_size_t)]

        encoded_length = len(component.encode("utf-16-le"))
        if encoded_length > 0xFFFC:
            return ("unsafe", None)
        name_buffer = ctypes.create_unicode_buffer(component)
        object_name = UnicodeString(
            encoded_length,
            encoded_length + 2,
            ctypes.cast(name_buffer, wintypes.LPWSTR),
        )
        object_attributes = ObjectAttributes(
            ctypes.sizeof(ObjectAttributes),
            wintypes.HANDLE(parent_handle),
            ctypes.pointer(object_name),
            0x00000040,
            None,
            None,
        )
        io_status = IoStatusBlock()
        ntdll = _windows_api(ctypes, "WinDLL")("ntdll")
        nt_open_file = ntdll.NtOpenFile
        nt_open_file.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            ctypes.POINTER(ObjectAttributes),
            ctypes.POINTER(IoStatusBlock),
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        nt_open_file.restype = wintypes.LONG
        raw_handle = wintypes.HANDLE()
        desired_access = 0x001000A0 if directory else 0x80100080
        open_options = 0x00200020 | (0x00000001 if directory else 0x00000040)
        status = nt_open_file(
            ctypes.byref(raw_handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            0x00000003,
            open_options,
        )
        if raw_handle.value is not None:
            owned_handle = int(raw_handle.value)
        if status < 0:
            rtl_status_to_error = ntdll.RtlNtStatusToDosError
            rtl_status_to_error.argtypes = [wintypes.LONG]
            rtl_status_to_error.restype = wintypes.ULONG
            return (_windows_error_reason(int(rtl_status_to_error(status))), None)
        if owned_handle is None:
            return ("operational", None)
        result = owned_handle
        owned_handle = None
        return (None, result)
    except BaseException:
        return ("operational", None)
    finally:
        name_buffer = None
        object_name = None
        object_attributes = None
        io_status = None
        if owned_handle is not None:
            _close_windows_handle(owned_handle)


def _open_windows_relative(parent_handle: int, component: str, *, directory: bool) -> int:
    """Open exactly one component relative to a validated directory handle."""
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        or "\x00" in component
    ):
        raise SafeOpenFailure("unsafe")
    reason, handle = _raw_windows_open_relative(parent_handle, component, directory=directory)
    if reason is not None or handle is None:
        raise SafeOpenFailure(reason or "operational")
    return handle


def _raw_windows_handle_information(
    handle: int,
) -> tuple[str | None, int | None, int | None]:
    """Query FileAttributeTagInfo without retaining native query failures."""
    import ctypes
    from ctypes import wintypes

    try:
        class AttributeTagInfo(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

        kernel32 = _windows_api(ctypes, "WinDLL")("kernel32", use_last_error=True)
        get_info = kernel32.GetFileInformationByHandleEx
        get_info.argtypes = [wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        info = AttributeTagInfo()
        if not get_info(wintypes.HANDLE(handle), 9, ctypes.byref(info), ctypes.sizeof(info)):
            return ("operational", None, None)
        return (None, int(info.attributes), int(info.tag))
    except BaseException:
        return ("operational", None, None)


def _raw_windows_final_path(handle: int) -> tuple[str | None, str | None]:
    """Query the normalized DOS path of an opened handle."""
    import ctypes
    from ctypes import wintypes

    try:
        kernel32 = _windows_api(ctypes, "WinDLL")("kernel32", use_last_error=True)
        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        get_final_path.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_final_path(wintypes.HANDLE(handle), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            return ("operational", None)
        return (None, buffer.value)
    except BaseException:
        return ("operational", None)


def _normalized_windows_handle_path(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def _windows_handle_reason(
    handle: int, *, directory: bool, root_final_path: str | None
) -> tuple[str | None, str | None]:
    info_reason, attributes, tag = _raw_windows_handle_information(handle)
    if info_reason is not None or attributes is None or tag is None:
        return ("operational", None)
    if attributes & 0x00000400 or tag:
        return ("unsafe", None)
    is_directory = bool(attributes & 0x00000010)
    if is_directory != directory:
        return ("unsafe", None)
    path_reason, final_path = _raw_windows_final_path(handle)
    if path_reason is not None or final_path is None:
        return ("operational", None)
    normalized = _normalized_windows_handle_path(final_path)
    if root_final_path is not None:
        try:
            if os.path.commonpath((root_final_path, normalized)) != root_final_path:
                return ("unsafe", None)
        except ValueError:
            return ("unsafe", None)
    return (None, normalized)


def _raw_windows_handle_to_file(
    handle: int,
) -> tuple[str | None, SafeRegularFile | None, bool]:
    """Transfer a validated native file handle to the CRT/Python stream layer."""
    import msvcrt

    descriptor: int | None = None
    transferred = False
    try:
        open_osfhandle = _windows_api(msvcrt, "open_osfhandle")
        binary_flag = _windows_api(os, "O_BINARY")
        descriptor = open_osfhandle(handle, os.O_RDONLY | binary_flag)
        transferred = True
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            return ("unsafe", None, transferred)
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = None
        return (None, SafeRegularFile(stream, file_stat.st_size), transferred)
    except BaseException:
        return ("operational", None, transferred)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                descriptor = None


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    try:
        kernel32 = _windows_api(ctypes, "WinDLL")("kernel32")
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(wintypes.HANDLE(handle))
    except BaseException:
        return


def _open_regular_windows(root: Path, relative: str) -> SafeRegularFile:
    """Walk descendants only through validated parent-relative native handles."""
    parts = _checked_relative_parts(relative)
    root_reason, root_handle = _raw_windows_open_root(root)
    if root_reason is not None or root_handle is None:
        raise SafeOpenFailure(root_reason or "operational")
    handles = [root_handle]
    final_handle: int | None = None
    try:
        root_validation, root_final_path = _windows_handle_reason(
            root_handle, directory=True, root_final_path=None
        )
        if root_validation is not None or root_final_path is None:
            raise SafeOpenFailure(root_validation or "operational")
        for component in parts[:-1]:
            child_handle = _open_windows_relative(handles[-1], component, directory=True)
            child_reason, _ = _windows_handle_reason(
                child_handle, directory=True, root_final_path=root_final_path
            )
            if child_reason is not None:
                _close_windows_handle(child_handle)
                raise SafeOpenFailure(child_reason)
            handles.append(child_handle)
        final_handle = _open_windows_relative(handles[-1], parts[-1], directory=False)
        final_reason, _ = _windows_handle_reason(
            final_handle, directory=False, root_final_path=root_final_path
        )
        if final_reason is not None:
            raise SafeOpenFailure(final_reason)
        transfer_reason, opened, transferred = _raw_windows_handle_to_file(final_handle)
        if transferred:
            final_handle = None
        if transfer_reason is not None or opened is None:
            raise SafeOpenFailure(transfer_reason or "operational")
        return opened
    finally:
        if final_handle is not None:
            _close_windows_handle(final_handle)
        for handle in reversed(handles):
            _close_windows_handle(handle)


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
