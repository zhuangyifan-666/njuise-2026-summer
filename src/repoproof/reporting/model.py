"""Canonical schema-1 projection of sanitized audit findings."""

import hashlib
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from repoproof import __version__
from repoproof.domain import AuditReport, ExitCode, Finding, FindingStatus, Location
from repoproof.profile.loader import profile_hash
from repoproof.profile.models import Profile

_MAX_TEXT_LENGTH = 1_000
_MAX_CREDENTIAL_VALUE_LENGTH = 255
_MAX_ASSIGNMENT_PADDING = 32
_MAX_ASSIGNMENT_PATTERN_LENGTH = (
    len("password")
    + _MAX_ASSIGNMENT_PADDING
    + 1
    + _MAX_ASSIGNMENT_PADDING
    + 1
    + _MAX_CREDENTIAL_VALUE_LENGTH
)
_MAX_TOKEN_PATTERN_LENGTH = len("github_pat_") + _MAX_CREDENTIAL_VALUE_LENGTH
_MAX_PEM_BEGIN_LENGTH = len("-----BEGIN OPENSSH PRIVATE KEY-----")
_SECRET_LOOKAHEAD = (
    max(
        _MAX_ASSIGNMENT_PATTERN_LENGTH,
        _MAX_TOKEN_PATTERN_LENGTH,
        _MAX_PEM_BEGIN_LENGTH,
    )
    + 1
)
_MAX_SANITIZER_SCAN_LENGTH = _MAX_TEXT_LENGTH + _SECRET_LOOKAHEAD
_STATUS_ORDER = {
    FindingStatus.FAIL: 0,
    FindingStatus.WARN: 1,
    FindingStatus.SKIP: 2,
    FindingStatus.PASS: 3,
}
_SUMMARY_STATUSES = (
    FindingStatus.FAIL,
    FindingStatus.WARN,
    FindingStatus.SKIP,
    FindingStatus.PASS,
)
_OSC_ESCAPE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_CSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PEM_BEGIN = re.compile(
    r"-----BEGIN (?P<label>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----",
    re.IGNORECASE,
)
_ASSIGNMENT_SECRET = re.compile(
    rf"\b(?:api[_-]?key|token|password|secret)"
    rf"[ \t]{{0,{_MAX_ASSIGNMENT_PADDING}}}[:=]"
    rf"[ \t]{{0,{_MAX_ASSIGNMENT_PADDING}}}['\"]?"
    rf"(?P<secret>[A-Za-z0-9_+/=-]{{20,{_MAX_CREDENTIAL_VALUE_LENGTH}}})"
    r"(?![A-Za-z0-9_+/=-])",
    re.IGNORECASE,
)
_TOKEN = re.compile(
    rf"(?<![A-Za-z0-9_])(?:"
    rf"gh[pousr]_[A-Za-z0-9]{{20,{_MAX_CREDENTIAL_VALUE_LENGTH}}}|"
    rf"github_pat_[A-Za-z0-9_]{{20,{_MAX_CREDENTIAL_VALUE_LENGTH}}}|"
    rf"sk-[A-Za-z0-9]{{16,{_MAX_CREDENTIAL_VALUE_LENGTH}}}|"
    r"AKIA[0-9A-Z]{16})(?![A-Za-z0-9_])"
)
_REDACTION_MARKER = re.compile(
    r"<redacted:(?:credential|token|private-key|path):[0-9a-f]{8}>"
)
_HIGH_ENTROPY = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9_])")
_SENSITIVE_SECRET_FILENAMES = frozenset({"id_rsa", "id_ed25519", ".env", "credentials.json"})
_SecretSpan = tuple[int, int, str, str]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def _redaction(kind: str, value: str) -> str:
    return f"<redacted:{kind}:{_fingerprint(value)}>"


def _has_high_entropy(value: str) -> bool:
    if len(value) < 32:
        return False
    frequencies = {character: value.count(character) / len(value) for character in set(value)}
    entropy = -sum(probability * math.log2(probability) for probability in frequencies.values())
    return entropy >= 3.5


def _normalize_controls(value: str) -> str:
    value = _OSC_ESCAPE.sub("", value)
    value = _CSI_ESCAPE.sub("", value)
    value = value.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    return "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )


def _private_key_spans(value: str) -> list[_SecretSpan]:
    """Locate complete or bounded-unterminated private-key PEM data."""
    spans: list[_SecretSpan] = []
    cursor = 0
    while match := _PEM_BEGIN.search(value, cursor):
        label = match.group("label")
        end = re.search(rf"-----END {re.escape(label)}-----", value[match.end() :], re.IGNORECASE)
        if end is None:
            stop = len(value)
            spans.append((match.start(), stop, "private-key", value[match.start() : stop]))
            break
        stop = match.end() + end.end()
        spans.append((match.start(), stop, "private-key", value[match.start() : stop]))
        cursor = stop
    return spans


def _overlaps_secret_span(start: int, stop: int, spans: Sequence[_SecretSpan]) -> bool:
    return any(start < span_stop and span_start < stop for span_start, span_stop, _, _ in spans)


def _secret_spans(value: str) -> list[_SecretSpan]:
    """Locate prioritized, non-overlapping secret spans in original text coordinates."""
    spans = _private_key_spans(value)
    for match in _ASSIGNMENT_SECRET.finditer(value):
        if not _overlaps_secret_span(match.start(), match.end(), spans):
            spans.append(
                (
                    match.start(),
                    match.end(),
                    "credential",
                    match.group("secret"),
                )
            )
    for match in _TOKEN.finditer(value):
        if not _overlaps_secret_span(match.start(), match.end(), spans):
            spans.append((match.start(), match.end(), "token", match.group(0)))
    return sorted(spans, key=lambda span: (span[0], span[1]))


def _redact_prefix(value: str, stop: int) -> str:
    """Render a source-coordinate prefix without letting replacements move its boundary."""
    redacted: list[str] = []
    cursor = 0
    for start, end, kind, fingerprint_value in _secret_spans(value):
        if start >= stop:
            break
        redacted.append(value[cursor:start])
        redacted.append(_redaction(kind, fingerprint_value))
        cursor = end
    redacted.append(value[cursor:stop])
    return "".join(redacted)


def sanitize_text(value: object) -> str:
    """Return deterministic bounded text that contains no raw recognized secret or control code."""
    try:
        raw = value if isinstance(value, str) else str(value)
        scan_was_bounded = len(raw) > _MAX_SANITIZER_SCAN_LENGTH
        text = _normalize_controls(raw[:_MAX_SANITIZER_SCAN_LENGTH])
        redacted = _redact_prefix(text, min(len(text), _MAX_TEXT_LENGTH))
        truncated = scan_was_bounded or len(text) > _MAX_TEXT_LENGTH
        if truncated:
            return (
                f"{redacted}<truncated:"
                f"{_fingerprint(text[:_MAX_TEXT_LENGTH])}>"
            )
        return redacted
    except BaseException:
        return "<unavailable>"


def sanitize_path(value: object) -> str:
    """Sanitize controls and explicit credential formats without changing ordinary path identity."""
    return sanitize_text(value)


def _sanitize_secret_scan_path(value: object) -> str:
    """Redact only sensitive or high-entropy filename components from secret-scan findings."""
    text = sanitize_path(value)
    parts = re.split(r"([/\\])", text)
    sanitized: list[str] = []
    for part in parts:
        if part in {"/", "\\"}:
            sanitized.append(part)
            continue
        if part.casefold() in _SENSITIVE_SECRET_FILENAMES:
            sanitized.append(_redaction("path", part))
        else:
            sanitized.append(
                ".".join(
                    _redaction("path", segment) if _has_high_entropy(segment) else segment
                    for segment in part.split(".")
                )
            )
    return "".join(sanitized)


def normalize_console_text(value: object) -> str:
    """Make any display value one line and inert without altering safe report semantics."""
    try:
        text = value if isinstance(value, str) else str(value)
        text = _normalize_controls(text)
        if len(text) > _MAX_TEXT_LENGTH:
            stop = _MAX_TEXT_LENGTH
            for marker in _REDACTION_MARKER.finditer(text):
                if marker.start() >= stop:
                    break
                if marker.end() > stop:
                    stop = marker.end()
                    break
            return f"{text[:stop]}<truncated:{_fingerprint(text)}>"
        return text
    except BaseException:
        return "<unavailable>"


def _location_key(location: Location) -> tuple[str, int, bool]:
    line = location.line if location.line is not None else -1
    return (location.path, line, location.line is None)


def _canonical_finding(finding: Finding, *, is_secret_scan: bool) -> Finding:
    sanitize_location = _sanitize_secret_scan_path if is_secret_scan else sanitize_path
    return replace(
        finding,
        rule_id=sanitize_text(finding.rule_id),
        message=sanitize_text(finding.message),
        locations=tuple(
            sorted(
                (Location(sanitize_location(item.path), item.line) for item in finding.locations),
                key=_location_key,
            )
        ),
        evidence_ids=tuple(sorted(sanitize_text(item) for item in finding.evidence_ids)),
        remediation=sanitize_text(finding.remediation),
    )


def _finding_key(finding: Finding) -> tuple[object, ...]:
    return (
        _STATUS_ORDER[finding.status],
        finding.rule_id,
        tuple(_location_key(location) for location in finding.locations),
        finding.severity.value,
        finding.message,
        finding.evidence_ids,
        finding.remediation,
    )


def build_report(
    profile: Profile,
    root: Path,
    findings: Sequence[Finding],
    diagnostics: Sequence[str],
    timings_ms: Mapping[str, int],
    generated_at: datetime,
) -> AuditReport:
    """Build the one immutable, deterministic report used by every renderer."""
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")

    rule_types = {rule.id: rule.type for rule in profile.rules}
    ordered_findings = tuple(
        sorted(
            (
                _canonical_finding(
                    item, is_secret_scan=rule_types.get(item.rule_id) == "secret_scan"
                )
                for item in findings
            ),
            key=_finding_key,
        )
    )
    exit_code = (
        ExitCode.FINDINGS
        if any(item.status is FindingStatus.FAIL for item in ordered_findings)
        else ExitCode.OK
    )
    return AuditReport(
        report_schema=1,
        tool_version=__version__,
        generated_at=generated_at.astimezone(UTC),
        repository_name=sanitize_path(root.name),
        profile_name=sanitize_text(profile.name),
        profile_schema=profile.schema,
        profile_hash=profile_hash(profile),
        findings=ordered_findings,
        manual_checks=tuple(sanitize_text(item) for item in profile.manual_checks),
        diagnostics=tuple(sanitize_text(item) for item in diagnostics),
        timings_ms=dict(sorted((sanitize_text(key), value) for key, value in timings_ms.items())),
        exit_code=exit_code,
    )


def _location_to_dict(location: Location) -> dict[str, object]:
    value: dict[str, object] = {"path": location.path}
    if location.line is not None:
        value["line"] = location.line
    return value


def report_to_dict(report: AuditReport) -> dict[str, object]:
    """Convert an :class:`AuditReport` to schema-1 JSON primitives only."""
    summary: dict[str, int] = {
        status.value: sum(item.status is status for item in report.findings)
        for status in _SUMMARY_STATUSES
    }
    summary["exit_code"] = int(report.exit_code)
    return {
        "report_schema": report.report_schema,
        "tool_version": report.tool_version,
        "generated_at": report.generated_at.astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": {"name": report.repository_name},
        "profile": {
            "name": report.profile_name,
            "schema": report.profile_schema,
            "sha256": report.profile_hash,
        },
        "summary": summary,
        "findings": [
            {
                "rule_id": item.rule_id,
                "status": item.status.value,
                "severity": item.severity.value,
                "message": item.message,
                "locations": [_location_to_dict(location) for location in item.locations],
                "evidence_ids": list(item.evidence_ids),
                "remediation": item.remediation,
            }
            for item in report.findings
        ],
        "manual_checks": list(report.manual_checks),
        "diagnostics": list(report.diagnostics),
        "timings_ms": dict(report.timings_ms),
    }
