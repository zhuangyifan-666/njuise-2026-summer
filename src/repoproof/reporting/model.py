"""Canonical schema-1 projection of audit findings."""

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from repoproof import __version__
from repoproof.domain import AuditReport, ExitCode, Finding, FindingStatus, Location
from repoproof.profile.loader import profile_hash
from repoproof.profile.models import Profile

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


def _location_key(location: Location) -> tuple[str, int, bool]:
    line = location.line if location.line is not None else -1
    return (location.path, line, location.line is None)


def _canonical_finding(finding: Finding) -> Finding:
    return replace(
        finding,
        locations=tuple(sorted(finding.locations, key=_location_key)),
        evidence_ids=tuple(sorted(finding.evidence_ids)),
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

    ordered_findings = tuple(
        sorted((_canonical_finding(item) for item in findings), key=_finding_key)
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
        repository_name=root.name,
        profile_name=profile.name,
        profile_schema=profile.schema,
        profile_hash=profile_hash(profile),
        findings=ordered_findings,
        manual_checks=tuple(profile.manual_checks),
        diagnostics=tuple(diagnostics),
        timings_ms=dict(sorted(timings_ms.items())),
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
