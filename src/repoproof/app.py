"""Injected orchestration for one deterministic repository audit."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic_ns

from repoproof.collectors.base import AuditContext, Collector
from repoproof.collectors.ci import CICollector
from repoproof.collectors.distribution import DistributionCollector
from repoproof.collectors.files import FileCollector
from repoproof.collectors.git import GitCollector
from repoproof.collectors.markdown import MarkdownCollector
from repoproof.collectors.secrets import SecretCollector
from repoproof.domain import AuditReport, Evidence
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile
from repoproof.reporting.model import build_report
from repoproof.rules import evaluate, required_collector_names


@dataclass(frozen=True, slots=True)
class AuditRequest:
    repository: Path
    profile: str = "ai4se-b"
    offline: bool = False


@dataclass(frozen=True, slots=True)
class AppDependencies:
    collectors: Mapping[str, Collector]
    clock: Callable[[], datetime]
    monotonic_ns: Callable[[], int]


def default_dependencies() -> AppDependencies:
    """Return the local collector registry used by the offline audit CLI."""
    return AppDependencies(
        collectors={
            "files": FileCollector(),
            "markdown": MarkdownCollector(),
            "ci": CICollector(),
            "distribution": DistributionCollector(),
            "git": GitCollector(),
            "secrets": SecretCollector(),
        },
        clock=lambda: datetime.now(UTC),
        monotonic_ns=monotonic_ns,
    )


def run_audit(request: AuditRequest, dependencies: AppDependencies) -> AuditReport:
    """Collect only required evidence, evaluate it, and build one canonical report."""
    try:
        root = request.repository.resolve(strict=False)
        is_directory = root.is_dir()
    except OSError:
        is_directory = False
    if not is_directory:
        raise RuntimeFailure(
            "Repository is not a readable directory.", "Check the repository path."
        )

    profile = load_profile(request.profile)
    snapshot_at = dependencies.clock()
    context = AuditContext(root, request.offline, snapshot_at=snapshot_at)
    evidence: list[Evidence] = []
    timings: dict[str, int] = {}
    for name in sorted(required_collector_names(profile, request.offline)):
        collector = dependencies.collectors.get(name)
        if collector is None:
            raise RuntimeFailure(
                f"Required collector {name!r} is unavailable.",
                "Use --offline or install the required audit component.",
            )
        started = dependencies.monotonic_ns()
        evidence.extend(collector.collect(context, profile))
        timings[name] = (dependencies.monotonic_ns() - started) // 1_000_000

    findings = evaluate(profile, evidence)
    return build_report(profile, root, findings, (), timings, snapshot_at)
