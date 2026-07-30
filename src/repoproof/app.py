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
from repoproof.domain import AuditReport, Evidence, EvidenceState
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
    github_collector_factory: Callable[[str | None], Collector] | None = None


def default_dependencies() -> AppDependencies:
    """Return the local collector registry used by the offline audit CLI."""
    import httpx
    import keyring

    from repoproof import __version__
    from repoproof.collectors.github import GitHubCollector
    from repoproof.credentials import CredentialStore
    from repoproof.github import GitHubGateway

    def github_factory(slug: str | None) -> Collector:
        gateway = GitHubGateway(
            CredentialStore(keyring.get_keyring()),
            httpx.Client(headers={"User-Agent": f"RepoProof/{__version__}"}),
        )
        return GitHubCollector(gateway, slug)

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
        github_collector_factory=github_factory,
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
    selected = required_collector_names(profile, request.offline)
    for name in (item for item in selected if item != "github"):
        collector = dependencies.collectors.get(name)
        if collector is None:
            raise RuntimeFailure(
                f"Required collector {name!r} is unavailable.",
                "Use --offline or install the required audit component.",
            )
        started = dependencies.monotonic_ns()
        evidence.extend(collector.collect(context, profile))
        timings[name] = (dependencies.monotonic_ns() - started) // 1_000_000

    if "github" in selected:
        git_evidence = next((item for item in evidence if item.kind == "git_history"), None)
        slug_value = (
            git_evidence.facts.get("repository_slug") if git_evidence is not None else None
        )
        slug = slug_value if isinstance(slug_value, str) else None
        started = dependencies.monotonic_ns()
        try:
            factory = dependencies.github_collector_factory
            if factory is None:
                raise RuntimeError
            evidence.extend(factory(slug).collect(context, profile))
        except Exception:
            evidence.append(
                Evidence(
                    "github:repository",
                    "github_repository",
                    ".",
                    EvidenceState.UNAVAILABLE,
                    {"reason": "remote_component_error", "runtime_error": True},
                    {},
                )
            )
        timings["github"] = (dependencies.monotonic_ns() - started) // 1_000_000

    findings = evaluate(profile, evidence)
    runtime_failed = any(bool(item.facts.get("runtime_error", False)) for item in evidence)
    diagnostics = ("github: remote evidence unavailable",) if runtime_failed else ()
    return build_report(
        profile,
        root,
        findings,
        diagnostics,
        timings,
        snapshot_at,
        runtime_failed=runtime_failed,
    )
