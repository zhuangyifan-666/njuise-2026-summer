from pathlib import Path
from unittest.mock import patch

import pytest

from repoproof.reporting.output import atomic_write_text


def test_atomic_write_uses_utf8_lf_and_creates_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "report.json"

    atomic_write_text(target, "first\r\nsecond\rthird")

    assert target.read_bytes() == b"first\nsecond\nthird"
    assert list(target.parent.glob(".report.json.*.tmp")) == []


def test_failed_replace_leaves_existing_report_intact_and_cleans_temp(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("old", encoding="utf-8")

    with patch("repoproof.reporting.output.os.replace", side_effect=OSError("blocked")):
        with pytest.raises(OSError, match="blocked"):
            atomic_write_text(report, "new")

    assert report.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_interrupted_write_cleans_temp_and_does_not_create_target(tmp_path: Path) -> None:
    target = tmp_path / "report.html"

    with patch("repoproof.reporting.output.os.fsync", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            atomic_write_text(target, "new")

    assert not target.exists()
    assert list(tmp_path.glob(".report.html.*.tmp")) == []
