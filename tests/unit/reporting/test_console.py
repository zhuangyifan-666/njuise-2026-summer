from datetime import UTC, datetime
from pathlib import Path

from repoproof.domain import Finding, FindingStatus, Severity
from repoproof.profile.loader import load_profile
from repoproof.reporting.console import render_console
from repoproof.reporting.model import build_report


def test_plain_console_has_no_ansi_hides_pass_and_uses_report_order() -> None:
    report = build_report(
        load_profile("ai4se-b"),
        Path("repo"),
        (
            Finding("z.pass", FindingStatus.PASS, Severity.ERROR, "ok", (), (), "none"),
            Finding("a.fail", FindingStatus.FAIL, Severity.ERROR, "missing", (), (), "fix it"),
        ),
        (),
        {},
        datetime(2026, 7, 29, tzinfo=UTC),
    )

    plain = render_console(report, color=False, verbose=False)
    verbose = render_console(report, color=False, verbose=True)

    assert "\x1b[" not in plain
    assert "[FAIL] a.fail: missing" in plain
    assert "z.pass" not in plain
    assert verbose.index("a.fail") < verbose.index("z.pass")
