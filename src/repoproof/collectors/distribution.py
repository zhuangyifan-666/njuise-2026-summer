import time
from pathlib import Path
from typing import cast

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken

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
MAX_WORKFLOW_ALIASES = 50
STRING_TAG = "tag:yaml.org,2002:str"
SEQUENCE_TAG = "tag:yaml.org,2002:seq"


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("Distribution collection timed out.", "Reduce repository scope.")


def _paths_exist(context: AuditContext, paths: tuple[str, ...], deadline: float) -> bool:
    for path in paths:
        _raise_if_timed_out(deadline)
        if not resolve_under_root(context.root, path).is_file():
            return False
    return True


def _mapping_value(mapping: MappingNode, key: str) -> Node | None:
    for node_key, node_value in mapping.value:
        if isinstance(node_key, ScalarNode) and node_key.value == key:
            return cast(Node, node_value)
    return None


def _has_tag_pattern(tags: Node | None) -> bool:
    if isinstance(tags, ScalarNode):
        return tags.tag == STRING_TAG and bool(tags.value.strip())
    if isinstance(tags, SequenceNode):
        return (
            tags.tag == SEQUENCE_TAG
            and bool(tags.value)
            and all(
                isinstance(tag, ScalarNode) and tag.tag == STRING_TAG and tag.value.strip()
                for tag in tags.value
            )
        )
    return False


def _is_release_workflow(path: Path, read_limit: int, deadline: float) -> bool:
    _raise_if_timed_out(deadline)
    if "release" not in path.name.casefold() or path.stat().st_size > read_limit:
        return False
    content = path.read_text(encoding="utf-8")
    aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(content))
    if aliases > MAX_WORKFLOW_ALIASES:
        raise yaml.YAMLError("alias limit exceeded")
    _raise_if_timed_out(deadline)
    document = yaml.compose(content, Loader=yaml.SafeLoader)
    _raise_if_timed_out(deadline)
    if not isinstance(document, MappingNode):
        return False
    trigger = _mapping_value(document, "on")
    if not isinstance(trigger, MappingNode):
        return False
    push = _mapping_value(trigger, "push")
    if not isinstance(push, MappingNode):
        return False
    return _has_tag_pattern(_mapping_value(push, "tags"))


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
        except yaml.YAMLError:
            state = EvidenceState.LIMITED
            facts = {"reason": "unsafe_or_invalid_workflow_yaml"}
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
