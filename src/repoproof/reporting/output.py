"""Safe atomic report-file output."""

import os
import tempfile
from pathlib import Path
from typing import TextIO


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
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
    stream_descriptor: int | None = None
    temp: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_temp = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temp = Path(raw_temp)
        stream: TextIO
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        stream_descriptor = descriptor
        descriptor = None
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
                _close_descriptor(stream_descriptor)
                stream_descriptor = None
        os.replace(temp, target)
        temp = None
    except BaseException:
        _close_descriptor(descriptor)
        _close_descriptor(stream_descriptor)
        _unlink_temp(temp)
        raise
