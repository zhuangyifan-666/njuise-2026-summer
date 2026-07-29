import stat
import time
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from yaml.tokens import AliasToken

from repoproof.collectors.files import _is_link_or_junction, _resolves_under_root
from repoproof.errors import UsageFailure
from repoproof.profile.models import SafeRepoPath

MAX_ALLOWLIST_BYTES = 1024 * 1024
MAX_ALLOWLIST_ALIASES = 50
_ALLOWLIST_NAME = ".repoproofallowlist.yml"


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    path: SafeRepoPath
    fingerprint: str = Field(pattern=r"^[0-9a-f]{8}$")


class SecretAllowlist(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = Field(alias="schema")
    entries: tuple[AllowlistEntry, ...] = ()


def _invalid_allowlist() -> UsageFailure:
    return UsageFailure(
        "Secret allowlist is invalid.",
        "Use only schema, rule_id, path, and 8-hex fingerprint fields.",
    )


def _raise_if_timed_out(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise UsageFailure(
            "Secret allowlist is invalid.", "Increase the audit timeout and try again."
        )


def load_secret_allowlist(
    root: Path, *, deadline: float | None = None
) -> frozenset[tuple[str, str, str]]:
    """Load only fingerprint-based suppressions from a checked in-root YAML file."""
    active_deadline = deadline if deadline is not None else time.monotonic() + 10.0
    _raise_if_timed_out(active_deadline)
    read_failed = False
    try:
        resolved_root = root.resolve(strict=True)
        path = resolved_root / _ALLOWLIST_NAME
        if not path.exists():
            return frozenset()
        path_stat = path.lstat()
        is_reparse = bool(
            getattr(path_stat, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        if (
            _is_link_or_junction(path)
            or is_reparse
            or not _resolves_under_root(resolved_root, path)
            or not path.is_file()
        ):
            raise _invalid_allowlist()
        if path_stat.st_size > MAX_ALLOWLIST_BYTES:
            raise UsageFailure("Secret allowlist exceeds 1 MiB.", "Reduce the allowlist size.")
        data = path.read_bytes()
    except UsageFailure:
        raise
    except OSError:
        read_failed = True
    if read_failed:
        raise _invalid_allowlist()
    _raise_if_timed_out(active_deadline)
    allowlist: SecretAllowlist | None = None
    try:
        text = data.decode("utf-8")
        aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
        if aliases > MAX_ALLOWLIST_ALIASES:
            raise ValueError
        document = yaml.safe_load(text)
        allowlist = SecretAllowlist.model_validate(document)
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError, ValueError):
        allowlist = None
    if allowlist is None:
        raise _invalid_allowlist()
    _raise_if_timed_out(active_deadline)
    return frozenset(
        (entry.rule_id, entry.path, entry.fingerprint) for entry in allowlist.entries
    )
