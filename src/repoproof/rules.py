"""Pure, deterministic evaluation of validated profile rules against collected evidence."""

from collections.abc import Iterable, Mapping, Sequence
from fnmatch import fnmatch

from repoproof.domain import (
    Evidence,
    EvidenceState,
    Finding,
    FindingStatus,
    Location,
    status_for_failure,
)
from repoproof.profile.models import (
    CIJobExistsRule,
    DistributionReadyRule,
    GitHistoryRule,
    MarkdownSectionsRule,
    PathExistsRule,
    Profile,
    Rule,
    SecretScanRule,
)


def required_collector_names(profile: Profile, offline: bool) -> tuple[str, ...]:
    """Return the smallest deterministic collector set for *profile*."""
    names: set[str] = set()
    collector_by_type = {
        "path_exists": "files",
        "markdown_sections": "markdown",
        "ci_job_exists": "ci",
        "git_history": "git",
        "distribution_ready": "distribution",
        "secret_scan": "secrets",
    }
    for rule in profile.rules:
        names.add(collector_by_type[rule.type])
        if isinstance(rule, DistributionReadyRule) and rule.params.required_paths:
            names.add("files")

    wants_remote = any(
        (
            isinstance(rule, GitHistoryRule)
            and rule.params.require_non_default_branch
            and rule.params.accept_remote_pr
        )
        or (
            isinstance(rule, DistributionReadyRule)
            and rule.params.require_release_workflow
            and rule.params.accept_published_release
        )
        for rule in profile.rules
    )
    if wants_remote and not offline:
        names.add("github")
    return tuple(sorted(names))


def _stable_value(value: object) -> tuple[object, ...]:
    """Produce a comparable representation without relying on mapping/set ordering."""
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int | float | str):
        return (type(value).__name__, value)
    if isinstance(value, Mapping):
        return (
            "mapping",
            tuple(sorted((str(key), _stable_value(item)) for key, item in value.items())),
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return ("sequence", tuple(sorted(_stable_value(item) for item in value)))
    return ("other", type(value).__module__, type(value).__qualname__)


def _evidence_key(item: Evidence) -> tuple[object, ...]:
    state_rank = 0 if item.state is EvidenceState.AVAILABLE else 1
    return (state_rank, item.id, _stable_value(item.facts), _stable_value(item.provenance))


def _find(evidence: Sequence[Evidence], kind: str, subject: str | None = None) -> Evidence | None:
    candidates = [
        item
        for item in evidence
        if item.kind == kind and (subject is None or item.subject == subject)
    ]
    return min(candidates, key=_evidence_key) if candidates else None


def _find_ci(evidence: Sequence[Evidence], rule: CIJobExistsRule) -> Evidence | None:
    expected_id = f"ci:{rule.params.ci}:{rule.params.path}"
    candidates = [
        item
        for item in evidence
        if (
            item.id == expected_id
            and item.kind == "ci_config"
            and item.subject == rule.params.path
            and item.provenance.get("ci") == rule.params.ci
        )
    ]
    return min(candidates, key=_evidence_key) if candidates else None


def _result(
    rule: Rule,
    passed: bool | None,
    message: str,
    evidence_ids: Iterable[str] = (),
    locations: Iterable[Location] = (),
) -> Finding:
    status = (
        FindingStatus.SKIP
        if passed is None
        else FindingStatus.PASS
        if passed
        else status_for_failure(rule.severity)
    )
    ordered_locations = tuple(sorted(set(locations), key=lambda item: (item.path, item.line or 0)))
    return Finding(
        rule.id,
        status,
        rule.severity,
        message,
        ordered_locations,
        tuple(sorted(set(evidence_ids))),
        rule.remediation,
    )


def _strings(value: object) -> tuple[str, ...] | None:
    if isinstance(value, str) or not isinstance(value, Iterable):
        return None
    result = tuple(str(item) for item in value)
    return tuple(sorted(set(result)))


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _path(rule: PathExistsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "file_inventory")
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "File inventory is unavailable.")
    paths = _strings(item.facts.get("paths"))
    if paths is None:
        return _result(rule, None, "File inventory is insufficient.", (item.id,))
    matched = tuple(
        sorted({path for pattern in rule.params.paths for path in paths if fnmatch(path, pattern)})
    )
    return _result(
        rule,
        len(matched) >= rule.params.min_matches,
        f"Matched {len(matched)} of {rule.params.min_matches} required paths.",
        (item.id,),
        (Location(path) for path in matched),
    )


def _normalize_heading(value: str) -> str:
    return " ".join(value.casefold().split())


def _completed_items(value: object) -> tuple[tuple[int, bool], ...] | None:
    if isinstance(value, str) or not isinstance(value, Iterable):
        return None
    items: list[tuple[int, bool]] = []
    for item in value:
        if not isinstance(item, Mapping):
            return None
        line = _integer(item.get("line"))
        has_commit = _boolean(item.get("has_commit"))
        if line is None or line < 1 or has_commit is None:
            return None
        items.append((line, has_commit))
    return tuple(sorted(set(items)))


def _markdown(rule: MarkdownSectionsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "markdown", rule.params.path)
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, f"Markdown evidence unavailable for {rule.params.path}.")
    headings = _strings(item.facts.get("headings"))
    checks = _completed_items(item.facts.get("completed_items"))
    if headings is None or checks is None:
        return _result(rule, None, "Markdown evidence is insufficient.", (item.id,))
    present = {_normalize_heading(value) for value in headings}
    headings_ok = all(
        any(
            _normalize_heading(choice) in present
            for choice in (heading, *rule.params.aliases.get(heading, ()))
        )
        for heading in rule.params.headings
    )
    missing_commits = tuple(line for line, has_commit in checks if not has_commit)
    commits_ok = not rule.params.completed_items_require_commit or not missing_commits
    return _result(
        rule,
        headings_ok and commits_ok,
        "Markdown headings and completed-item evidence checked.",
        (item.id,),
        (Location(rule.params.path, line) for line in missing_commits),
    )


def _ci(rule: CIJobExistsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find_ci(evidence, rule)
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, f"CI evidence unavailable for {rule.params.path}.")
    jobs = _strings(item.facts.get("jobs"))
    if jobs is None:
        return _result(rule, None, "CI evidence is insufficient.", (item.id,))
    return _result(
        rule,
        rule.params.job in jobs,
        f"CI job {rule.params.job!r} checked.",
        (item.id,),
        (Location(rule.params.path),),
    )


def _remote_process(remote: Evidence | None) -> tuple[bool | None, str | None]:
    if remote is None or remote.state is not EvidenceState.AVAILABLE:
        return (None, None)
    count = _integer(remote.facts.get("merged_pull_requests"))
    return (count > 0, remote.id) if count is not None and count >= 0 else (None, remote.id)


def _alternatives(*values: bool | None) -> bool | None:
    """Combine accepted proof alternatives without turning unknown evidence into false."""
    if any(value is True for value in values):
        return True
    if any(value is None for value in values):
        return None
    return False


def _git(rule: GitHistoryRule, evidence: Sequence[Evidence]) -> Finding:
    local = _find(evidence, "git_history")
    if local is None or local.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Local Git history is unavailable.")
    commits = _integer(local.facts.get("commit_count"))
    if commits is None or commits < 0:
        return _result(rule, None, "Local Git history is insufficient.", (local.id,))
    if commits < rule.params.min_commits:
        return _result(rule, False, "Git history has too few commits.", (local.id,))
    if not rule.params.require_non_default_branch:
        return _result(rule, True, "Git history requirements checked.", (local.id,))

    default = local.facts.get("default_branch")
    branches = _strings(local.facts.get("branches"))
    if not isinstance(default, str) or not default or branches is None or default not in branches:
        return _result(rule, None, "Git branch evidence is insufficient.", (local.id,))
    if not any(branch != default for branch in branches):
        return _result(rule, False, "No non-default branch evidence.", (local.id,))

    local_process: bool | None = False
    if rule.params.accept_local_merge:
        merges = _integer(local.facts.get("merge_count"))
        if merges is None or merges < 0:
            local_process = None
        else:
            local_process = merges > 0
    alternatives: list[bool | None] = []
    if rule.params.accept_local_merge:
        alternatives.append(local_process)
    evidence_ids: tuple[str, ...] = (local.id,)
    if rule.params.accept_remote_pr:
        remote = _find(evidence, "github_repository")
        remote_process, remote_id = _remote_process(remote)
        alternatives.append(remote_process)
        if remote_id is not None:
            evidence_ids = (*evidence_ids, remote_id)
    process = _alternatives(*alternatives)
    if process is True:
        return _result(rule, True, "Git history requirements checked.", evidence_ids)
    if process is None:
        return _result(rule, None, "Git process evidence is unavailable.", evidence_ids)
    return _result(rule, False, "No accepted merge or pull request evidence.", evidence_ids)


def _distribution(rule: DistributionReadyRule, evidence: Sequence[Evidence]) -> Finding:
    local = _find(evidence, "distribution")
    if local is None or local.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Distribution evidence is unavailable.")
    packaging = _strings(local.facts.get("packaging"))
    if packaging is None:
        return _result(rule, None, "Distribution evidence is insufficient.", (local.id,))
    if not any(item in rule.params.allowed for item in packaging):
        return _result(rule, False, "No allowed packaging evidence found.", (local.id,))

    evidence_ids: tuple[str, ...] = (local.id,)
    if rule.params.required_paths:
        inventory = _find(evidence, "file_inventory")
        if inventory is None or inventory.state is not EvidenceState.AVAILABLE:
            return _result(rule, None, "Required-path evidence is unavailable.", evidence_ids)
        paths = _strings(inventory.facts.get("paths"))
        if paths is None:
            return _result(
                rule,
                None,
                "Required-path evidence is insufficient.",
                (*evidence_ids, inventory.id),
            )
        evidence_ids = (*evidence_ids, inventory.id)
        if not all(path in paths for path in rule.params.required_paths):
            return _result(rule, False, "Required distribution paths are missing.", evidence_ids)

    if not rule.params.require_release_workflow:
        return _result(rule, True, "Packaging and release readiness checked.", evidence_ids)
    local_release = _boolean(local.facts.get("release_workflow"))
    alternatives: list[bool | None] = [local_release]
    if rule.params.accept_published_release:
        remote = _find(evidence, "github_repository")
        if remote is None or remote.state is not EvidenceState.AVAILABLE:
            alternatives.append(None)
        else:
            has_release = _boolean(remote.facts.get("has_release"))
            alternatives.append(has_release)
            evidence_ids = (*evidence_ids, remote.id)
    release = _alternatives(*alternatives)
    if release is True:
        return _result(rule, True, "Packaging and release readiness checked.", evidence_ids)
    if release is None:
        return _result(rule, None, "Release evidence is unavailable.", evidence_ids)
    return _result(rule, False, "No release evidence found.", evidence_ids)


def _secret_matches(
    value: object, rule: SecretScanRule
) -> tuple[tuple[str, str, int, str], ...] | None:
    if isinstance(value, str) or not isinstance(value, Iterable):
        return None
    matches: set[tuple[str, str, int, str]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            return None
        category = item.get("category")
        path = item.get("path")
        line = _integer(item.get("line"))
        fingerprint = item.get("fingerprint")
        triggered = _strings(item.get("triggered_for"))
        allowlisted = _strings(item.get("allowlisted_for"))
        if (
            not isinstance(category, str)
            or not isinstance(path, str)
            or line is None
            or line < 1
            or not isinstance(fingerprint, str)
            or triggered is None
            or allowlisted is None
        ):
            return None
        if (
            category in rule.params.categories
            and not any(fnmatch(path, pattern) for pattern in rule.params.exclude_paths)
            and rule.id in triggered
            and rule.id not in allowlisted
        ):
            matches.add((path, category, line, fingerprint))
    return tuple(sorted(matches))


def _secret(rule: SecretScanRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "secret_scan")
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Secret scan evidence is unavailable.")
    matches = _secret_matches(item.facts.get("matches"), rule)
    if matches is None:
        return _result(rule, None, "Secret scan evidence is insufficient.", (item.id,))
    locations = (Location(path, line) for path, _category, line, _fingerprint in matches)
    safe_details = ", ".join(
        f"{category} fingerprint={fingerprint}" for _path, category, _line, fingerprint in matches
    )
    message = (
        "Secret scan found no suspected values."
        if not matches
        else f"Secret scan found {len(matches)} suspected values: <redacted>; {safe_details}."
    )
    return _result(rule, not matches, message, (item.id,), locations)


def _evaluate_rule(rule: Rule, evidence: Sequence[Evidence]) -> Finding:
    if isinstance(rule, PathExistsRule):
        return _path(rule, evidence)
    if isinstance(rule, MarkdownSectionsRule):
        return _markdown(rule, evidence)
    if isinstance(rule, CIJobExistsRule):
        return _ci(rule, evidence)
    if isinstance(rule, GitHistoryRule):
        return _git(rule, evidence)
    if isinstance(rule, DistributionReadyRule):
        return _distribution(rule, evidence)
    if isinstance(rule, SecretScanRule):
        return _secret(rule, evidence)
    raise AssertionError(f"Unsupported validated rule: {type(rule).__name__}")


def evaluate(profile: Profile, evidence: Sequence[Evidence]) -> tuple[Finding, ...]:
    """Evaluate every profile rule in deterministic rule-id order."""
    return tuple(
        sorted(
            (_evaluate_rule(rule, evidence) for rule in profile.rules),
            key=lambda item: item.rule_id,
        )
    )
