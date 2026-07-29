from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
import math
import os
import re
import time
from pathlib import Path

from repoproof.allowlist import load_secret_allowlist
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.collectors.files import RepositoryFile, repository_files
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import Profile, SecretScanRule
from repoproof.security import SafeOpenFailure, SafeRegularFile, open_regular_file, short_fingerprint

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
_PATTERN_TAIL_BYTES = 512
_MAX_REPORTED_MATCHES = 10_000


class _ScanStatus(StrEnum):
    OK = "ok"
    LIMITED = "limited"
    TIMED_OUT = "timed_out"
    READ_FAILED = "read_failed"
    CLASSIFIER_FAILED = "classifier_failed"
    DISCARDED = "discarded"


@dataclass(frozen=True, slots=True)
class _SafeMatch:
    key: tuple[str, str, int, str]
    value: dict[str, object]


def shannon_entropy(value: str) -> float:
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
    triggered_ids: tuple[str, ...],
    allowlist: frozenset[tuple[str, str, str]],
    relative: str,
    fingerprint: str,
) -> tuple[str, ...]:
    return tuple(
        rule_id
        for rule_id in triggered_ids
        if (rule_id, relative, fingerprint) in allowlist
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
            if not any(
                _applicable_rules(rules, file.relative, category)
                for category in ("token", "private_key", "high_entropy", "sensitive_file")
            ):
                continue
            limited = self._add_sensitive_filename(file, rules, allowlist, matches, seen) or limited
            if limited or file.size > context.max_read_bytes:
                continue
            try:
                opened = open_regular_file(root, file.relative)
            except SafeOpenFailure:
                continue
            if opened.size > context.max_read_bytes:
                opened.close()
                continue
            status, file_matches = self._scan_raw_file(
                opened,
                file.relative,
                context.max_read_bytes,
                rules,
                allowlist,
                deadline,
            )
            if status is _ScanStatus.TIMED_OUT:
                raise RuntimeFailure("Secret scan timed out.", "Reduce scope or ignored paths.")
            if status is _ScanStatus.READ_FAILED:
                raise RuntimeFailure(
                    "Unable to read repository file.", "Check repository readability or reduce scope."
                )
            if status is _ScanStatus.CLASSIFIER_FAILED:
                raise RuntimeFailure(
                    "Secret scan classification failed.", "Reduce scope or ignored paths."
                )
            if status is _ScanStatus.DISCARDED:
                continue
            for match in file_matches:
                if match.key not in seen:
                    seen.add(match.key)
                    matches.append(match.value)
                    limited = len(matches) >= _MAX_REPORTED_MATCHES
                    if limited:
                        break
            if limited or status is _ScanStatus.LIMITED:
                limited = True
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

    def _add_sensitive_filename(
        self,
        file: RepositoryFile,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        matches: list[dict[str, object]],
        seen: set[tuple[str, str, int, str]],
    ) -> bool:
        triggered = _applicable_rules(rules, file.relative, "sensitive_file")
        if file.path.name.casefold() not in SENSITIVE_NAMES or not triggered:
            return False
        fingerprint = short_fingerprint(file.relative.encode())
        key = ("sensitive_file", file.relative, 1, fingerprint)
        if key not in seen:
            seen.add(key)
            ids = tuple(sorted(rule.id for rule in triggered))
            matches.append(
                {
                    "category": "sensitive_file",
                    "path": file.relative,
                    "line": 1,
                    "fingerprint": fingerprint,
                    "allowlisted_for": _allowlisted_for(ids, allowlist, file.relative, fingerprint),
                }
            )
        return len(matches) >= _MAX_REPORTED_MATCHES

    def _scan_raw_file(
        self,
        opened: SafeRegularFile,
        relative: str,
        max_read_bytes: int,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
        deadline: float,
    ) -> tuple[_ScanStatus, tuple[_SafeMatch, ...]]:
        """Read/classify raw bytes without allowing their frame into an outward traceback."""
        fragment = b""
        tail = b""
        window = b""
        local_matches: list[_SafeMatch] = []
        line_number = 1
        remaining = max_read_bytes
        first = True
        try:
            with opened.stream:
                while remaining > 0:
                    fragment = opened.stream.read(min(_READ_CHUNK_BYTES, remaining))
                    if not fragment:
                        break
                    remaining -= len(fragment)
                    if first and b"\x00" in fragment:
                        return (_ScanStatus.DISCARDED, ())
                    first = False
                    for part, newline in self._physical_parts(fragment):
                        window = tail + part
                        cutoff = len(window) if newline else max(0, len(window) - _PATTERN_TAIL_BYTES)
                        local_matches.extend(
                            self._classify(window, cutoff, relative, line_number, rules, allowlist)
                        )
                        tail = b"" if newline else window[-_PATTERN_TAIL_BYTES:]
                        if newline:
                            line_number += 1
                    _raise_if_timed_out(deadline)
                if tail:
                    local_matches.extend(
                        self._classify(tail, len(tail), relative, line_number, rules, allowlist)
                    )
                if os.fstat(opened.stream.fileno()).st_size > max_read_bytes:
                    return (_ScanStatus.DISCARDED, ())
                return (_ScanStatus.OK, tuple(local_matches))
        except RuntimeFailure:
            return (_ScanStatus.TIMED_OUT, ())
        except OSError:
            return (_ScanStatus.READ_FAILED, ())
        except Exception:
            return (_ScanStatus.CLASSIFIER_FAILED, ())
        finally:
            fragment = b""
            tail = b""
            window = b""

    @staticmethod
    def _physical_parts(fragment: bytes) -> tuple[tuple[bytes, bool], ...]:
        parts: list[tuple[bytes, bool]] = []
        start = 0
        while True:
            newline = fragment.find(b"\n", start)
            if newline < 0:
                parts.append((fragment[start:], False))
                return tuple(parts)
            parts.append((fragment[start : newline + 1], True))
            start = newline + 1

    @staticmethod
    def _classify(
        window: bytes,
        cutoff: int,
        relative: str,
        line_number: int,
        rules: tuple[SecretScanRule, ...],
        allowlist: frozenset[tuple[str, str, str]],
    ) -> tuple[_SafeMatch, ...]:
        found_matches: list[_SafeMatch] = []
        token_rules = _applicable_rules(rules, relative, "token")
        if token_rules:
            for pattern in TOKEN_PATTERNS:
                for found in pattern.finditer(window):
                    if found.end() <= cutoff:
                        found_matches.append(
                            SecretCollector._safe_match(
                                "token",
                                found.group(0),
                                tuple(sorted(rule.id for rule in token_rules)),
                                relative,
                                line_number,
                                allowlist,
                            )
                        )
        private_rules = _applicable_rules(rules, relative, "private_key")
        if private_rules:
            for found in PRIVATE_KEY.finditer(window):
                if found.end() <= cutoff:
                    found_matches.append(
                        SecretCollector._safe_match(
                            "private_key",
                            found.group(0),
                            tuple(sorted(rule.id for rule in private_rules)),
                            relative,
                            line_number,
                            allowlist,
                        )
                    )
        entropy_rules = _applicable_rules(rules, relative, "high_entropy")
        for found in ASSIGNMENT.finditer(window):
            if found.end(1) > cutoff:
                continue
            raw = found.group(1)
            entropy = shannon_entropy(raw.decode("ascii", "ignore"))
            triggered = tuple(
                sorted(rule.id for rule in entropy_rules if entropy >= rule.params.entropy_threshold)
            )
            if triggered:
                found_matches.append(
                    SecretCollector._safe_match(
                        "high_entropy", raw, triggered, relative, line_number, allowlist
                    )
                )
        return tuple(found_matches)

    @staticmethod
    def _safe_match(
        category: str,
        raw: bytes,
        triggered_ids: tuple[str, ...],
        relative: str,
        line_number: int,
        allowlist: frozenset[tuple[str, str, str]],
    ) -> _SafeMatch:
        fingerprint = short_fingerprint(raw)
        key = (category, relative, line_number, fingerprint)
        return _SafeMatch(
            key,
            {
                "category": category,
                "path": relative,
                "line": line_number,
                "fingerprint": fingerprint,
                "allowlisted_for": _allowlisted_for(
                    triggered_ids, allowlist, relative, fingerprint
                ),
            },
        )
