import re
import time
from pathlib import Path

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import Profile
from repoproof.security import resolve_under_root

PACKAGING = {
    "python": ("pyproject.toml", "repoproof.spec"),
    "docker": ("Dockerfile",),
    "npm": ("package.json",),
    "cargo": ("Cargo.toml",),
}
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
RELEASE_TAG_TRIGGER_RE = re.compile(r"^\s*tags\s*:", re.MULTILINE)


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("Distribution collection timed out.", "Reduce repository scope.")


def _paths_exist(context: AuditContext, paths: tuple[str, ...], deadline: float) -> bool:
    for path in paths:
        _raise_if_timed_out(deadline)
        if not resolve_under_root(context.root, path).is_file():
            return False
    return True


def _is_release_workflow(path: Path, read_limit: int, deadline: float) -> bool:
    _raise_if_timed_out(deadline)
    if "release" not in path.name.casefold() or path.stat().st_size > read_limit:
        return False
    content = path.read_text(encoding="utf-8")
    _raise_if_timed_out(deadline)
    return bool(RELEASE_TAG_TRIGGER_RE.search(content))


class DistributionCollector:
    name = "distribution"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        del profile
        deadline = time.monotonic() + context.timeout_seconds
        read_limit = min(context.max_read_bytes, MAX_WORKFLOW_BYTES)
        try:
            packaging = tuple(
                name
                for name, paths in PACKAGING.items()
                if _paths_exist(context, paths, deadline)
            )
            _raise_if_timed_out(deadline)
            workflows = resolve_under_root(context.root, ".github/workflows")
            release_workflow = False
            workflow_count = 0
            if workflows.is_dir():
                root = context.root.resolve(strict=True)
                for pattern in ("*.yml", "*.yaml"):
                    for candidate in workflows.glob(pattern):
                        _raise_if_timed_out(deadline)
                        workflow_count += 1
                        if workflow_count > context.max_files:
                            raise RuntimeFailure(
                                "Repository exceeds candidate file limit.",
                                "Reduce scope or ignored paths.",
                            )
                        relative = candidate.relative_to(root).as_posix()
                        path = resolve_under_root(context.root, relative)
                        if path.is_file() and _is_release_workflow(path, read_limit, deadline):
                            release_workflow = True
                            break
                    if release_workflow:
                        break
            _raise_if_timed_out(deadline)
            state = EvidenceState.AVAILABLE
            facts: dict[str, object] = {
                "packaging": packaging,
                "release_workflow": release_workflow,
            }
        except (OSError, UnicodeDecodeError):
            state = EvidenceState.LIMITED
            facts = {"reason": "unreadable_repository"}
        return (
            Evidence(
                "distribution:local",
                "distribution",
                ".",
                state,
                facts,
                collector_provenance(context, self.name),
            ),
        )
