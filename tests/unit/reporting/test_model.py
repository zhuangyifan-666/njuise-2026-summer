from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from repoproof import __version__
from repoproof.domain import ExitCode, Finding, FindingStatus, Location, Severity
from repoproof.profile.loader import load_profile, profile_hash
from repoproof.reporting.model import build_report, report_to_dict


def test_report_has_deterministic_order_stable_metadata_and_utc_timestamp() -> None:
    profile = load_profile("ai4se-b")
    findings = (
        Finding("z.pass", FindingStatus.PASS, Severity.ERROR, "ok", (), (), "none"),
        Finding(
            "a.fail",
            FindingStatus.FAIL,
            Severity.ERROR,
            "bad",
            (Location("z.md", 2), Location("a.md", 1)),
            (),
            "fix",
        ),
        Finding("a.warn", FindingStatus.WARN, Severity.WARNING, "warn", (), (), "fix"),
    )
    generated_at = datetime(2026, 7, 29, 8, 0, tzinfo=timezone(timedelta(hours=8)))

    report = build_report(profile, Path("repo"), findings, (), {"z": 2, "a": 1}, generated_at)
    payload = report_to_dict(report)

    assert [finding.rule_id for finding in report.findings] == ["a.fail", "a.warn", "z.pass"]
    assert [(location.path, location.line) for location in report.findings[0].locations] == [
        ("a.md", 1),
        ("z.md", 2),
    ]
    assert report.generated_at == datetime(2026, 7, 29, tzinfo=UTC)
    assert report.tool_version == __version__
    assert report.profile_hash == profile_hash(profile)
    assert report.exit_code is ExitCode.FINDINGS
    assert payload["generated_at"] == "2026-07-29T00:00:00Z"
    assert payload["profile"] == {
        "name": profile.name,
        "schema": 1,
        "sha256": profile_hash(profile),
    }
    assert payload["summary"] == {"FAIL": 1, "WARN": 1, "SKIP": 0, "PASS": 1, "exit_code": 1}
    assert payload["timings_ms"] == {"a": 1, "z": 2}


def test_report_rejects_naive_generated_at() -> None:
    with pytest.raises(ValueError, match="generated_at must be timezone-aware"):
        build_report(
            load_profile("ai4se-b"),
            Path("repo"),
            (),
            (),
            {},
            datetime(2026, 7, 29),
        )
