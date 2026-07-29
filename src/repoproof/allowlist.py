import os
import time
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field
from yaml.nodes import MappingNode, Node, SequenceNode
from yaml.tokens import AliasToken

from repoproof.errors import UsageFailure
from repoproof.profile.models import SafeRepoPath
from repoproof.security import SafeOpenFailure, open_regular_file

MAX_ALLOWLIST_BYTES = 1024 * 1024
MAX_ALLOWLIST_ALIASES = 50
MAX_ALLOWLIST_DEPTH = 32
MAX_ALLOWLIST_NODES = 10_000
MAX_ALLOWLIST_CONTAINER_ITEMS = 1_000
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


class _AllowlistStatus(StrEnum):
    MISSING = "missing"
    VALID = "valid"
    TOO_LARGE = "too_large"
    INVALID = "invalid"
    TIMED_OUT = "timed_out"


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


def _validate_yaml_structure(document: Node | None) -> bool:
    if document is None:
        return False
    stack: list[tuple[Node, int]] = [(document, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_ALLOWLIST_NODES or depth > MAX_ALLOWLIST_DEPTH:
            return False
        if isinstance(node, MappingNode):
            if len(node.value) > MAX_ALLOWLIST_CONTAINER_ITEMS:
                return False
            for key, value in node.value:
                stack.extend(((key, depth + 1), (value, depth + 1)))
        elif isinstance(node, SequenceNode):
            if len(node.value) > MAX_ALLOWLIST_CONTAINER_ITEMS:
                return False
            stack.extend((item, depth + 1) for item in node.value)
    return True


def _load_raw_allowlist(
    root: Path, deadline: float
) -> tuple[_AllowlistStatus, SecretAllowlist | None]:
    """Contain all raw YAML/parser objects so no outward exception can retain them."""
    data = b""
    text = ""
    nodes: Node | None = None
    document: object | None = None
    handle = None
    try:
        if time.monotonic() >= deadline:
            return (_AllowlistStatus.TIMED_OUT, None)
        try:
            handle = open_regular_file(root, _ALLOWLIST_NAME)
        except SafeOpenFailure:
            if not (root / _ALLOWLIST_NAME).exists():
                return (_AllowlistStatus.MISSING, None)
            return (_AllowlistStatus.INVALID, None)
        if handle.size > MAX_ALLOWLIST_BYTES:
            return (_AllowlistStatus.TOO_LARGE, None)
        data = handle.stream.read(MAX_ALLOWLIST_BYTES + 1)
        if (
            len(data) > MAX_ALLOWLIST_BYTES
            or os.fstat(handle.stream.fileno()).st_size > MAX_ALLOWLIST_BYTES
        ):
            return (_AllowlistStatus.TOO_LARGE, None)
        text = data.decode("utf-8")
        if sum(isinstance(token, AliasToken) for token in yaml.scan(text)) > MAX_ALLOWLIST_ALIASES:
            return (_AllowlistStatus.INVALID, None)
        nodes = yaml.compose(text, Loader=yaml.SafeLoader)
        if not _validate_yaml_structure(nodes):
            return (_AllowlistStatus.INVALID, None)
        document = yaml.safe_load(text)
        model = SecretAllowlist.model_validate(document)
        if time.monotonic() >= deadline:
            return (_AllowlistStatus.TIMED_OUT, None)
        return (_AllowlistStatus.VALID, model)
    except Exception:
        return (_AllowlistStatus.INVALID, None)
    finally:
        if handle is not None:
            handle.close()
        data = b""
        text = ""
        nodes = None
        document = None


def load_secret_allowlist(
    root: Path, *, deadline: float | None = None
) -> frozenset[tuple[str, str, str]]:
    """Load only fingerprint-based suppressions from a checked in-root YAML file."""
    active_deadline = deadline if deadline is not None else time.monotonic() + 10.0
    status, allowlist = _load_raw_allowlist(root, active_deadline)
    if status is _AllowlistStatus.MISSING:
        return frozenset()
    if status is _AllowlistStatus.TOO_LARGE:
        raise UsageFailure("Secret allowlist exceeds 1 MiB.", "Reduce the allowlist size.")
    if status is _AllowlistStatus.TIMED_OUT:
        _raise_if_timed_out(active_deadline)
    if status is not _AllowlistStatus.VALID or allowlist is None:
        raise _invalid_allowlist()
    return frozenset((entry.rule_id, entry.path, entry.fingerprint) for entry in allowlist.entries)
