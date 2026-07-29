from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from repoproof.domain import Evidence
from repoproof.profile.models import Profile


@dataclass(frozen=True, slots=True)
class AuditContext:
    root: Path
    offline: bool
    max_files: int = 20_000
    max_total_bytes: int = 500 * 1024 * 1024
    max_read_bytes: int = 2 * 1024 * 1024
    timeout_seconds: float = 10.0
    snapshot_at: datetime = datetime(1970, 1, 1, tzinfo=UTC)


class Collector(Protocol):
    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]: ...


def collector_provenance(
    context: AuditContext, name: str, **extra: object
) -> dict[str, object]:
    return {
        "collector": name,
        "version": 1,
        "time": context.snapshot_at.isoformat().replace("+00:00", "Z"),
        **extra,
    }
