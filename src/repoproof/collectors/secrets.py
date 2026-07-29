import math
import re
import time
from collections import Counter
from fnmatch import fnmatch
from pathlib import Path

from repoproof.allowlist import load_secret_allowlist
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.collectors.files import (
    RepositoryFile,
    _is_link_or_junction,
    _resolves_under_root,
    repository_files,
)
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import Profile, SecretScanRule
from repoproof.security import short_fingerprint

TOKEN_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
ASSIGNMENT = re.compile(
    rb"(?i)(?:token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_+/=-]{20,255})"
)
SENSITIVE_NAMES = frozenset({"id_rsa", "id_ed25519", ".env", "credentials.json"})
_READ_CHUNK_BYTES = 8192
_PATTERN_TAIL_BYTES = 256
_MAX_REPORTED_MATCHES = 10_000


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy in bits per symbol for an ASCII candidate."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("Secret scan timed out.", "Reduce scope or ignored paths.")


def _is_excluded(relative: str, rule: SecretScanRule) -> bool:
    return any(fnmatch(relative, pattern) for pattern in rule.params.exclude_paths)


def _applicable_rules(
    rules: tuple[SecretScanRule, ...], relative: str, category: str
) -> tuple[SecretScanRule, ...]:
    return tuple(
        rule
        for rule in rules
        if category in rule.params.categories and not _is_excluded(relative, rule)
    )


def _allowlisted_for(
    rules: tuple[SecretScanRule, ...],
    allowlist: frozenset[tuple[str, str, str]],
    relative: str,
    category: str,
    fingerprint: str,
) -> tuple[str, ...]:
    return tuple(
        rule.id
        for rule in _applicable_rules(rules, relative, category)
        if (rule.id, relative, fingerprint) in allowlist
    )


class SecretCollector:
    name = "secrets"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        rules = tuple(rule for rule in profile.rules if isinstance(rule, SecretScanRule))
        if not rules:
            return ()
        deadline = time.monotonic() + context.timeout_seconds
        _raise_if_timed_out(deadline)
        try:
            root = context.root.resolve(strict=True)
        except OSError:
            raise RuntimeFailure(
                "Unable to enumerate repository.", "Check repository readability or reduce scope."
            ) from None
        allowlist = load_secret_allowlist(root, deadline=deadline)
        files = repository_files(context, deadline=deadline)
        matches: list[dict[str, object]] = []
        seen: set[tuple[str, str, int, str]] = set()
        limited = False
        for file in files:
            _raise_if_timed_out(deadline)
            if not self._safe_candidate(root, file):
                continue
            if not any(
                _applicable_rules(rules, file.relative, category)
                for category in ("token", "private_key", "high_entropy", "sensitive_file")
            ):
                continue
            limited = self._scan_file(
                file,
                context.max_read_bytes,
                rules,
                allowlist,
                deadline,
                matches,
                seen,
            ) or limited
            if limited:
                break
        facts: dict[str, object] = {"matches": tuple(matches)}
        state = EvidenceState.LIMITED if limited else EvidenceState.AVAILABLE
        if limited:
            facts["reason"] = "match_limit"
        return (
            Evidence(
                id="secrets:scan",
                kind="secret_scan",
                subject=".",
                state=state,
                facts=facts,
                provenance=collector_provenance(context, self.name),
            ),
        )

    @staticmethod
    def _safe_candidate(root: Path, file: RepositoryFile) -> bool:
        return not _is_link_or_junction(file.path) and _resolves_under_root(root, file.path)

    def _scan_file(
        self,
        file: RepositoryFile,
        max_read_bytes: int,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        deadline: float,
        matches: list[dict[str, object]],
        seen: set[tuple[str, str, int, str]],
    ) -> bool:
        limited = self._add_sensitive_filename(file, rules, allowlist, matches, seen)
        if limited or file.size > max_read_bytes:
            return limited
        try:
            with file.path.open("rb") as source:
                first_chunk = source.read(min(_READ_CHUNK_BYTES, max_read_bytes))
                if b"\x00" in first_chunk:
                    return False
                source.seek(0)
                line_number = 1
                tail = b""
                remaining = max_read_bytes
                while remaining > 0 and (
                    fragment := source.readline(min(_READ_CHUNK_BYTES, remaining))
                ):
                    _raise_if_timed_out(deadline)
                    remaining -= len(fragment)
                    window = tail + fragment
                    if self._classify(
                        window, file.relative, line_number, rules, allowlist, matches, seen
                    ):
                        return True
                    tail = window[-_PATTERN_TAIL_BYTES:]
                    if fragment.endswith(b"\n"):
                        line_number += 1
                        tail = b""
        except OSError:
            raise RuntimeFailure(
                "Unable to read repository file.", "Check repository readability or reduce scope."
            ) from None
        return False

    def _add_sensitive_filename(
        self,
        file: RepositoryFile,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        matches: list[dict[str, object]],
        seen: set[tuple[str, str, int, str]],
    ) -> bool:
        if file.path.name.casefold() not in SENSITIVE_NAMES:
            return False
        fingerprint = short_fingerprint(file.relative.encode())
        return self._append_match(
            "sensitive_file", file.relative, 1, fingerprint, rules, allowlist, matches, seen
        )

    def _classify(
        self,
        window: bytes,
        relative: str,
        line_number: int,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        matches: list[dict[str, object]],
        seen: set[tuple[str, str, int, str]],
    ) -> bool:
        candidates: list[tuple[str, bytes]] = []
        if _applicable_rules(rules, relative, "token"):
            candidates.extend(
                ("token", found.group(0))
                for pattern in TOKEN_PATTERNS
                for found in pattern.finditer(window)
            )
        if _applicable_rules(rules, relative, "private_key"):
            candidates.extend(
                ("private_key", found.group(0)) for found in PRIVATE_KEY.finditer(window)
            )
        high_entropy_rules = _applicable_rules(rules, relative, "high_entropy")
        if high_entropy_rules:
            for found in ASSIGNMENT.finditer(window):
                raw = found.group(1)
                entropy = shannon_entropy(raw.decode("ascii", "ignore"))
                if any(entropy >= rule.params.entropy_threshold for rule in high_entropy_rules):
                    candidates.append(("high_entropy", raw))
        for category, raw in candidates:
            if self._append_match(
                category,
                relative,
                line_number,
                short_fingerprint(raw),
                rules,
                allowlist,
                matches,
                seen,
            ):
                return True
        return False

    @staticmethod
    def _append_match(
        category: str,
        relative: str,
        line_number: int,
        fingerprint: str,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        matches: list[dict[str, object]],
        seen: set[tuple[str, str, int, str]],
    ) -> bool:
        key = (category, relative, line_number, fingerprint)
        if key in seen:
            return False
        seen.add(key)
        matches.append(
            {
                "category": category,
                "path": relative,
                "line": line_number,
                "fingerprint": fingerprint,
                "allowlisted_for": _allowlisted_for(
                    rules, allowlist, relative, category, fingerprint
                ),
            }
        )
        return len(matches) >= _MAX_REPORTED_MATCHES
