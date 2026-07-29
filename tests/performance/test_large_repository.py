from pathlib import Path
from time import perf_counter

import pytest

from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import FileCollector
from repoproof.profile.loader import load_profile


@pytest.mark.performance
def test_ten_thousand_file_inventory_finishes_within_fifteen_seconds(tmp_path: Path) -> None:
    for index in range(10_000):
        (tmp_path / f"file-{index:05}.txt").write_text("x", encoding="utf-8")

    started = perf_counter()
    evidence = FileCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))
    elapsed = perf_counter() - started

    assert len(evidence[0].facts["paths"]) == 10_000
    assert elapsed < 15.0
