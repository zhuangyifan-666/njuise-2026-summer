import time

import yaml
from yaml.tokens import AliasToken

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import CIJobExistsRule, Profile
from repoproof.security import resolve_under_root

MAX_CI_BYTES = 2 * 1024 * 1024
MAX_YAML_ALIASES = 50
GITLAB_RESERVED = {
    "default",
    "include",
    "stages",
    "variables",
    "workflow",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
    "spec",
}


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("CI collection timed out.", "Reduce CI configuration input size.")


def _is_job(ci_type: str, key: object, value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if ci_type == "gitlab":
        return str(key) not in GITLAB_RESERVED
    return "runs-on" in value or "uses" in value


def _jobs(ci_type: str, mapping: dict[object, object]) -> tuple[str, ...]:
    if ci_type == "github":
        github_jobs = mapping.get("jobs")
        if not isinstance(github_jobs, dict):
            return ()
        return tuple(
            sorted(str(key) for key, value in github_jobs.items() if isinstance(value, dict))
        )
    return tuple(sorted(str(key) for key, value in mapping.items() if _is_job(ci_type, key, value)))


def _document_mapping(ci_type: str, text: str) -> dict[object, object]:
    documents = list(yaml.safe_load_all(text))
    if (
        ci_type == "gitlab"
        and len(documents) == 2
        and isinstance(documents[0], dict)
        and "spec" in documents[0]
        and isinstance(documents[1], dict)
    ):
        return documents[1]
    if len(documents) == 1 and isinstance(documents[0], dict):
        return documents[0]
    if len(documents) <= 1:
        return {}
    raise yaml.YAMLError("unsupported YAML document topology")


class CICollector:
    name = "ci"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        deadline = time.monotonic() + context.timeout_seconds
        read_limit = min(context.max_read_bytes, MAX_CI_BYTES)
        specs = sorted(
            {
                (rule.params.ci, rule.params.path)
                for rule in profile.rules
                if isinstance(rule, CIJobExistsRule)
            }
        )
        evidence: list[Evidence] = []
        for ci_type, subject in specs:
            _raise_if_timed_out(deadline)
            path = resolve_under_root(context.root, subject)
            state = EvidenceState.UNAVAILABLE
            facts: dict[str, object] = {}
            try:
                if path.is_file():
                    if path.stat().st_size > read_limit:
                        state = EvidenceState.LIMITED
                        facts = {"reason": "file_too_large"}
                    else:
                        text = path.read_text(encoding="utf-8")
                        aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
                        if aliases > MAX_YAML_ALIASES:
                            raise yaml.YAMLError("alias limit exceeded")
                        _raise_if_timed_out(deadline)
                        mapping = _document_mapping(ci_type, text)
                        _raise_if_timed_out(deadline)
                        facts = {"jobs": _jobs(ci_type, mapping)}
                        state = EvidenceState.AVAILABLE
            except (UnicodeDecodeError, yaml.YAMLError):
                state = EvidenceState.LIMITED
                facts = {"reason": "unsafe_or_invalid_yaml"}
            except OSError:
                state = EvidenceState.LIMITED
                facts = {"reason": "unreadable_file"}
            evidence.append(
                Evidence(
                    f"ci:{ci_type}:{subject}",
                    "ci_config",
                    subject,
                    state,
                    facts,
                    collector_provenance(context, self.name, ci=ci_type),
                )
            )
        return tuple(evidence)
