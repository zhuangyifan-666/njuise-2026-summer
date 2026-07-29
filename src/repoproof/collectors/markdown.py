import re
import time

from markdown_it import MarkdownIt

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import MarkdownSectionsRule, Profile
from repoproof.security import resolve_under_root

MAX_MARKDOWN_BYTES = 2 * 1024 * 1024
COMMIT_RE = re.compile(r"(?<![0-9a-z])(?:[0-9a-f]{7,40})(?![0-9a-z])", re.IGNORECASE)
CHECKED_RE = re.compile(r"^\s*[-*+]\s+\[[xX]\]\s+")


def _normalize_heading(value: str) -> str:
    return " ".join(value.casefold().split())


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeFailure("Markdown collection timed out.", "Reduce Markdown input size.")


class MarkdownCollector:
    name = "markdown"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        deadline = time.monotonic() + context.timeout_seconds
        read_limit = min(context.max_read_bytes, MAX_MARKDOWN_BYTES)
        subjects = sorted(
            {rule.params.path for rule in profile.rules if isinstance(rule, MarkdownSectionsRule)}
        )
        evidence: list[Evidence] = []
        for subject in subjects:
            _raise_if_timed_out(deadline)
            path = resolve_under_root(context.root, subject)
            try:
                if not path.is_file():
                    evidence.append(
                        Evidence(
                            f"markdown:{subject}",
                            "markdown",
                            subject,
                            EvidenceState.UNAVAILABLE,
                            {},
                            collector_provenance(context, self.name),
                        )
                    )
                    continue
                if path.stat().st_size > read_limit:
                    evidence.append(
                        Evidence(
                            f"markdown:{subject}",
                            "markdown",
                            subject,
                            EvidenceState.LIMITED,
                            {"reason": "file_too_large"},
                            collector_provenance(context, self.name),
                        )
                    )
                    continue
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                evidence.append(
                    Evidence(
                        f"markdown:{subject}",
                        "markdown",
                        subject,
                        EvidenceState.LIMITED,
                        {"reason": "invalid_utf8"},
                        collector_provenance(context, self.name),
                    )
                )
                continue
            except OSError:
                evidence.append(
                    Evidence(
                        f"markdown:{subject}",
                        "markdown",
                        subject,
                        EvidenceState.LIMITED,
                        {"reason": "unreadable_file"},
                        collector_provenance(context, self.name),
                    )
                )
                continue
            _raise_if_timed_out(deadline)
            tokens = MarkdownIt().parse(text)
            _raise_if_timed_out(deadline)
            headings = tuple(
                _normalize_heading(tokens[index + 1].content)
                for index, token in enumerate(tokens[:-1])
                if token.type == "heading_open"
            )
            completed_items = tuple(
                {"line": line_number, "has_commit": bool(COMMIT_RE.search(line))}
                for line_number, line in enumerate(text.splitlines(), start=1)
                if CHECKED_RE.match(line)
            )
            evidence.append(
                Evidence(
                    f"markdown:{subject}",
                    "markdown",
                    subject,
                    EvidenceState.AVAILABLE,
                    {"headings": headings, "completed_items": completed_items},
                    collector_provenance(context, self.name),
                )
            )
        return tuple(evidence)
