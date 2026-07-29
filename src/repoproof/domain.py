from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum


class FindingStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


class EvidenceState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    LIMITED = "limited"


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    USAGE = 2
    RUNTIME = 3


def status_for_failure(severity: Severity) -> FindingStatus:
    return FindingStatus.FAIL if severity is Severity.ERROR else FindingStatus.WARN


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    subject: str
    state: EvidenceState
    facts: Mapping[str, object]
    provenance: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    status: FindingStatus
    severity: Severity
    message: str
    locations: tuple[Location, ...]
    evidence_ids: tuple[str, ...]
    remediation: str


@dataclass(frozen=True, slots=True)
class AuditReport:
    report_schema: int
    tool_version: str
    generated_at: datetime
    repository_name: str
    profile_name: str
    profile_schema: int
    profile_hash: str
    findings: tuple[Finding, ...]
    manual_checks: tuple[str, ...]
    diagnostics: tuple[str, ...]
    timings_ms: Mapping[str, int]
    exit_code: ExitCode
