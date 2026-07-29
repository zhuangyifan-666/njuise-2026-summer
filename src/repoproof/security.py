import hashlib
from pathlib import Path

from repoproof.errors import UsageFailure


def resolve_under_root(root: Path, candidate: str) -> Path:
    relative = Path(candidate)
    if relative.is_absolute():
        raise UsageFailure("Profile paths must be relative.", "Use a repository-relative path.")
    if ".." in relative.parts:
        raise UsageFailure(
            "Path resolves outside repository.", "Remove traversal or external links."
        )
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / relative).resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise UsageFailure(
            "Path resolves outside repository.", "Remove traversal or external links."
        ) from exc
    return resolved


def short_fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    redacted = text
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    return redacted
