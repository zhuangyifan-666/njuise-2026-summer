import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from repoproof.domain import AuditReport, Finding, FindingStatus, Location, Severity
from repoproof.profile.models import Profile
from repoproof.reporting.console import render_console
from repoproof.reporting.html_reporter import render_html
from repoproof.reporting.json_reporter import render_json
from repoproof.reporting.model import build_report, report_to_dict


class _PayloadBodyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.payload: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "body":
            self.payload = dict(attrs).get("data-report")


def _profile() -> Profile:
    return Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test profile",
            "manual_checks": ["review architecture"],
            "rules": [
                {
                    "id": "docs.present",
                    "type": "path_exists",
                    "severity": "error",
                    "params": {"paths": ["README.md"]},
                    "remediation": "add README",
                }
            ],
        }
    )


def _report():
    return build_report(
        _profile(),
        Path("demo-repository"),
        (
            Finding(
                "docs.present",
                FindingStatus.FAIL,
                Severity.ERROR,
                "README is missing",
                (Location("README.md", 4),),
                ("files.inventory",),
                "add README",
            ),
        ),
        ("filesystem inventory was partial",),
        {"files": 7},
        datetime(2026, 7, 29, tzinfo=UTC),
    )


def _report_with_message(message: str) -> AuditReport:
    return build_report(
        _profile(),
        Path("demo-repository"),
        (
            Finding(
                "docs.present",
                FindingStatus.FAIL,
                Severity.ERROR,
                message,
                (),
                (),
                "add README",
            ),
        ),
        (),
        {},
        datetime(2026, 7, 29, tzinfo=UTC),
    )


def _console_payload(rendered: str) -> dict[str, object]:
    for line in rendered.splitlines():
        if line.startswith("semantic-json: "):
            return json.loads(line.removeprefix("semantic-json: "))
    raise AssertionError("console did not include a semantic payload")


def _message_from_payload(payload: dict[str, object]) -> str:
    findings = payload["findings"]
    assert isinstance(findings, list)
    finding = findings[0]
    assert isinstance(finding, dict)
    message = finding["message"]
    assert isinstance(message, str)
    return message


def _messages_from_all_surfaces(report: AuditReport) -> tuple[str, ...]:
    html_parser = _PayloadBodyParser()
    html_parser.feed(render_html(report))
    assert html_parser.payload is not None
    return (
        report.findings[0].message,
        render_console(report, color=False, verbose=False),
        _message_from_payload(json.loads(render_json(report))),
        _message_from_payload(json.loads(html_parser.payload)),
    )


def test_verbose_renderers_decode_to_the_same_schema_payload() -> None:
    report = _report()
    expected = report_to_dict(report)
    html_parser = _PayloadBodyParser()
    html_parser.feed(render_html(report))

    assert json.loads(render_json(report)) == expected
    assert _console_payload(render_console(report, color=False, verbose=True)) == expected
    assert html_parser.payload is not None
    assert json.loads(html_parser.payload) == expected


def test_console_normalizes_hostile_control_sequences_and_ignores_ambient_width(
    monkeypatch,
) -> None:
    report = _report()
    hostile = "first\nsecond\r\x1b[31mred\x1b]8;;https://evil.example\x07link\x1b\\\u202eevil"
    hostile_finding = replace(
        report.findings[0],
        rule_id=hostile,
        message=hostile,
        locations=(Location(hostile, 4),),
        evidence_ids=(hostile,),
        remediation=hostile,
    )
    report = replace(
        report,
        repository_name=hostile,
        profile_name=hostile,
        findings=(hostile_finding,),
        manual_checks=(hostile,),
        diagnostics=(hostile,),
        timings_ms={hostile: 7},
    )

    monkeypatch.setenv("COLUMNS", "40")
    narrow = render_console(report, color=False, verbose=True)
    monkeypatch.setenv("COLUMNS", "200")
    wide = render_console(report, color=False, verbose=True)
    colored = render_console(report, color=True, verbose=True)

    assert narrow == wide
    assert "first\\nsecond" in narrow
    assert "\x1b" not in narrow and "\u202e" not in narrow
    assert all(ord(char) >= 32 or char == "\n" for char in narrow)
    assert hostile not in re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", colored)


def test_report_model_redacts_recognized_canary_from_every_semantic_surface() -> None:
    canary = "ghp_0123456789ABCDEF0123456789ABCDEF0123"
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": f"policy-{canary}",
            "description": "test profile",
            "manual_checks": [f"review {canary}"],
            "rules": [
                {
                    "id": "docs.safe",
                    "type": "path_exists",
                    "severity": "error",
                    "params": {"paths": ["README.md"]},
                    "remediation": "add README",
                }
            ],
        }
    )
    report = build_report(
        profile,
        Path(canary),
        (
            Finding(
                canary,
                FindingStatus.FAIL,
                Severity.ERROR,
                f"token={canary}",
                (Location(f"private/{canary}.pem", 1),),
                (canary,),
                f"remove {canary}",
            ),
            Finding("docs.safe", FindingStatus.PASS, Severity.ERROR, "normal text", (), (), "none"),
        ),
        (f"diagnostic {canary}",),
        {canary: 1},
        datetime(2026, 7, 29, tzinfo=UTC),
    )

    surfaces = (
        repr(report),
        repr(report_to_dict(report)),
        render_console(report, color=False, verbose=True),
        render_json(report),
        render_html(report),
    )

    assert all(canary not in surface for surface in surfaces)
    assert "docs.safe" in render_json(report)
    assert "<redacted:" in render_json(report)


def test_sanitization_preserves_benign_identity_and_only_redacts_explicit_secrets() -> None:
    long_identifier = "build-0123456789abcdef0123456789abcdef0123456789abcdef"
    sha256_identifier = "a" * 64
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": "private-project",
            "description": "test profile",
            "manual_checks": ["token=optional"],
            "rules": [
                {
                    "id": "docs.present",
                    "type": "path_exists",
                    "severity": "error",
                    "params": {"paths": ["README.md"]},
                    "remediation": "add README",
                }
            ],
        }
    )
    report = build_report(
        profile,
        Path("ordinary-repository"),
        (
            Finding(
                "docs.present",
                FindingStatus.FAIL,
                Severity.ERROR,
                f"token=optional; identifier={long_identifier}",
                (Location("certificates/public.pem", 8),),
                (sha256_identifier,),
                "keep private-project documentation",
            ),
        ),
        ("private-project diagnostics",),
        {long_identifier: 9},
        datetime(2026, 7, 29, tzinfo=UTC),
    )

    finding = report.findings[0]
    assert report.profile_name == "private-project"
    assert report.manual_checks == ("token=optional",)
    assert finding.rule_id == "docs.present"
    assert finding.locations == (Location("certificates/public.pem", 8),)
    assert finding.evidence_ids == (sha256_identifier,)
    assert long_identifier in finding.message
    assert report.timings_ms == {long_identifier: 9}


def test_secret_scan_location_redacts_only_high_entropy_filename_component() -> None:
    token_like_filename = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": "test-policy",
            "description": "test profile",
            "rules": [
                {
                    "id": "security.secrets",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["high_entropy"]},
                    "remediation": "remove secret",
                }
            ],
        }
    )
    report = build_report(
        profile,
        Path("repo"),
        (
            Finding(
                "security.secrets",
                FindingStatus.FAIL,
                Severity.ERROR,
                "secret scan finding",
                (Location(f"captures/{token_like_filename}.txt", 3),),
                ("secrets:scan",),
                "remove secret",
            ),
        ),
        (),
        {},
        datetime(2026, 7, 29, tzinfo=UTC),
    )

    location = report.findings[0].locations[0]
    assert location.path.startswith("captures/")
    assert token_like_filename not in location.path
    assert "<redacted:path:" in location.path


def test_private_key_blocks_and_hidden_secret_segments_do_not_reach_any_renderer() -> None:
    pem_body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAAAAAABAAAAAEAAA=="
    unterminated_body = "MIIEpAIBAAKCAQEAprivatebody"
    private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{pem_body}\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    unterminated = f"-----BEGIN RSA PRIVATE KEY-----\n{unterminated_body}"
    secret_segments = (
        ".ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
        "name.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
    )
    profile = Profile.model_validate(
        {
            "schema": 1,
            "name": "private-project",
            "description": "test profile",
            "rules": [
                {
                    "id": "security.secrets",
                    "type": "secret_scan",
                    "severity": "error",
                    "params": {"categories": ["private_key", "high_entropy"]},
                    "remediation": "remove secret",
                }
            ],
        }
    )
    report = build_report(
        profile,
        Path("repo"),
        (
            Finding(
                "security.secrets",
                FindingStatus.FAIL,
                Severity.ERROR,
                f"{private_key}\n{unterminated}",
                tuple(Location(f"captures/{segment}", 1) for segment in secret_segments),
                ("secrets:scan",),
                "remove secret",
            ),
        ),
        (),
        {},
        datetime(2026, 7, 29, tzinfo=UTC),
    )

    surfaces = (
        repr(report),
        repr(report_to_dict(report)),
        render_console(report, color=False, verbose=True),
        render_json(report),
        render_html(report),
    )
    assert all(private_key not in surface and unterminated not in surface for surface in surfaces)
    assert all(pem_body not in surface and unterminated_body not in surface for surface in surfaces)
    assert all(segment not in repr(report) for segment in secret_segments)
    assert report.profile_name == "private-project"
    assert "<redacted:private-key:" in report.findings[0].message


@pytest.mark.parametrize("start", (999, 1000, 1001), ids=("before", "at", "after"))
@pytest.mark.parametrize(
    ("credential", "secret"),
    (
        ("ghp_GithubBoundaryCanary0123456789ABCD", "GithubBoundaryCanary0123456789ABCD"),
        (
            "github_pat_GithubBoundaryCanary0123456789ABCD",
            "GithubBoundaryCanary0123456789ABCD",
        ),
        ("api_key = 'ApiKeyBoundaryCanary0123456789ABCD", "ApiKeyBoundaryCanary0123456789ABCD"),
        ("token:TokenBoundaryCanary0123456789ABCD", "TokenBoundaryCanary0123456789ABCD"),
        ("password = PasswordBoundaryCanary0123456789ABCD", "PasswordBoundaryCanary0123456789ABCD"),
        ("secret=SecretBoundaryCanary0123456789ABCD", "SecretBoundaryCanary0123456789ABCD"),
    ),
    ids=("ghp", "github-pat", "api-key", "token", "password", "secret"),
)
def test_credentials_across_report_cutoff_leave_no_raw_fragment_in_any_surface(
    start: int, credential: str, secret: str
) -> None:
    filler = "~" * start
    report = build_report(
        _profile(),
        Path("demo-repository"),
        (
            Finding(
                "docs.present",
                FindingStatus.FAIL,
                Severity.ERROR,
                f"{filler}{credential}:tail",
                (),
                (),
                "add README",
            ),
        ),
        (),
        {},
        datetime(2026, 7, 29, tzinfo=UTC),
    )
    raw_prefix = credential[: max(0, 1000 - start)]
    surfaces = (
        repr(report),
        repr(report_to_dict(report)),
        render_console(report, color=False, verbose=True),
        render_json(report),
        render_html(report),
    )

    assert raw_prefix == "" or all(f"{filler}{raw_prefix}" not in item for item in surfaces)
    assert all(secret[:20] not in item and secret[-20:] not in item for item in surfaces)
    assert all(credential not in item for item in surfaces)


def test_secret_replacements_preserve_raw_cutoff_in_every_report_surface() -> None:
    assignments = "|".join(
        f"password{' ' * 32}={' ' * 32}'{character * 255}"
        for character in ("A", "B", "C")
    )
    raw_cutoff = f"{assignments}|SAFE-BOUND"
    tail_token = "github_pat_" + ("R" * 255)
    message = f"{raw_cutoff}{'~' * 300}{tail_token}"
    assert len(assignments) == 989
    assert len(raw_cutoff) == 1_000
    assert message[1_300:] == tail_token

    messages = _messages_from_all_surfaces(_report_with_message(message))

    assert all("SAFE-BOUND" in item for item in messages)
    assert all(tail_token[:30] not in item for item in messages)
    assert all(
        character * 20 not in item
        for item in messages
        for character in ("A", "B", "C")
    )


def test_boundary_overlapping_assignment_and_token_use_one_complete_redaction() -> None:
    token = "ghp_" + ("O" * 251)
    messages = _messages_from_all_surfaces(
        _report_with_message(f"{'~' * 990}token={token}")
    )
    expected = "<redacted:credential:0d4b4e83>"

    assert all(expected in item for item in messages)
    assert all(item.count("<redacted:") == 1 for item in messages)
    assert all("<redacted:token:" not in item for item in messages)
    assert all("token=" not in item and "ghp_" not in item for item in messages)
    assert all("O" * 20 not in item for item in messages)


def test_boundary_private_key_uses_one_complete_redaction() -> None:
    pem_body = "PEM_BOUNDARY_CANARY_BODY"
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{pem_body}\n"
        "-----END RSA PRIVATE KEY-----"
    )
    messages = _messages_from_all_surfaces(
        _report_with_message(f"{'~' * 990}{pem}")
    )
    expected = "<redacted:private-key:4f817529>"

    assert all(expected in item for item in messages)
    assert all(item.count("<redacted:") == 1 for item in messages)
    assert all("BEGIN RSA" not in item and "END RSA" not in item for item in messages)
    assert all(pem_body not in item for item in messages)
