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
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_ASSIGNMENT_SECRET = re.compile(
    r"\b(?P<label>api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?"
    r"(?P<secret>[A-Za-z0-9_+/=-]{20,255})",
    re.IGNORECASE,
)
_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})(?![A-Za-z0-9_])"
)
_HIGH_ENTROPY = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9_])")
_SENSITIVE_SECRET_FILENAMES = frozenset({"id_rsa", "id_ed25519", ".env", "credentials.json"})


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


def _redact_secrets(value: str) -> str:
    value = _PRIVATE_KEY.sub(lambda match: _redaction("private-key", match.group(0)), value)
    value = _ASSIGNMENT_SECRET.sub(
        lambda match: f"{match.group('label')}={_redaction('credential', match.group('secret'))}",
        value,
    )
    value = _TOKEN.sub(lambda match: _redaction("token", match.group(0)), value)
    return value


def sanitize_text(value: object) -> str:
    """Return deterministic bounded text that contains no raw recognized secret or control code."""
    try:
        text = value if isinstance(value, str) else str(value)
        text = _redact_secrets(_normalize_controls(text))
        if len(text) > _MAX_TEXT_LENGTH:
            return f"{text[:_MAX_TEXT_LENGTH]}<truncated:{_fingerprint(text)}>"
        return text
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
        stem, dot, suffix = part.rpartition(".")
        entropy_candidate = stem if dot else part
        if part.casefold() in _SENSITIVE_SECRET_FILENAMES:
            sanitized.append(_redaction("path", part))
        elif _has_high_entropy(entropy_candidate):
            sanitized.append(f"{_redaction('path', entropy_candidate)}{dot}{suffix}")
        else:
            sanitized.append(part)
    return "".join(sanitized)


def normalize_console_text(value: object) -> str:
    """Make any display value one line and inert without altering safe report semantics."""
    try:
        text = value if isinstance(value, str) else str(value)
        text = _normalize_controls(text)
        if len(text) > _MAX_TEXT_LENGTH:
            return f"{text[:_MAX_TEXT_LENGTH]}<truncated:{_fingerprint(text)}>"
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
