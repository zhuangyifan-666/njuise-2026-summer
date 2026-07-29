"""Safe atomic report-file output."""

import os
import tempfile
from pathlib import Path


def atomic_write_text(target: Path, content: str) -> None:
    """Write UTF-8 LF text through a same-directory temporary file and replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temp = Path(raw_temp)
    descriptor_open = True
    try:
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor_open = False
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        if descriptor_open:
            os.close(descriptor)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Preserve the original write/replace error without including report content.
            pass
        raise
