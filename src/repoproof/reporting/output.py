"""Safe atomic report-file output."""

import os
import tempfile
from pathlib import Path
from typing import TextIO

type DescriptorIdentity = tuple[int, int]


def _descriptor_identity(descriptor: int) -> DescriptorIdentity | None:
    try:
        info = os.fstat(descriptor)
        return (info.st_dev, info.st_ino)
    except OSError:
        return None


def _close_descriptor(descriptor: int | None, identity: DescriptorIdentity | None = None) -> None:
    if descriptor is None:
        return
    try:
        if identity is not None:
            try:
                if _descriptor_identity(descriptor) != identity:
                    return
            except BaseException:
                return
        os.close(descriptor)
    except BaseException:
        return


def _unlink_temp(temp: Path | None) -> None:
    if temp is None:
        return
    try:
        temp.unlink()
    except BaseException:
        return


def atomic_write_text(target: Path, content: str) -> None:
    """Write UTF-8 LF text atomically while preserving the first failure and traceback."""
    descriptor: int | None = None
    descriptor_identity: DescriptorIdentity | None = None
    temp: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_temp = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temp = Path(raw_temp)
        descriptor_identity = _descriptor_identity(descriptor)
        stream: TextIO
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n", closefd=False)
        primary_failure = False
        try:
            normalized = content.replace("\r\n", "\n").replace("\r", "\n")
            stream.write(normalized)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            primary_failure = True
            raise
        finally:
            try:
                stream.close()
            except BaseException:
                if not primary_failure:
                    raise
            finally:
                _close_descriptor(descriptor, descriptor_identity)
                descriptor = None
        os.replace(temp, target)
        temp = None
    except BaseException:
        _close_descriptor(descriptor, descriptor_identity)
        _unlink_temp(temp)
        raise
