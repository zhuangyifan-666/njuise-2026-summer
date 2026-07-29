"""Sanitized, HTTPS-only access to the small GitHub evidence surface."""

import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, TypeVar, cast
from urllib.parse import urlsplit

import httpx

from repoproof.credentials import normalize_host
from repoproof.errors import UsageFailure

_T = TypeVar("_T")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,255}")
_ACTIONS_STATUS = re.compile(r"[a-z_]{1,32}")


class CredentialReader(Protocol):
    def get(self, host: str) -> str | None: ...


class GitHubTokenMissing(RuntimeError):
    """A safe, deterministic signal that optional credentials are absent."""

    def __init__(self) -> None:
        super().__init__("GitHub token is not configured")


class GitHubRequestError(RuntimeError):
    """A detached error that contains no request, response, or remote body."""

    def __init__(self) -> None:
        super().__init__("GitHub request failed safely")


class _RequestStatus(StrEnum):
    OK = "ok"
    ABSENT = "absent"
    REQUEST_FAILED = "request_failed"


def safe_repository_coordinates(owner: str, repo: str) -> tuple[str, str] | None:
    """Validate path segments before they are interpolated into an API URL."""
    if (
        not isinstance(owner, str)
        or not isinstance(repo, str)
        or _OWNER.fullmatch(owner) is None
        or _REPOSITORY.fullmatch(repo) is None
        or repo in {".", ".."}
    ):
        return None
    return (owner, repo)


def _repository_payload(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError
    branch = value.get("default_branch")
    if not isinstance(branch, str) or _BRANCH.fullmatch(branch) is None:
        raise ValueError
    return {"default_branch": branch}


def _pull_request_count(value: object) -> int:
    if isinstance(value, str) or not isinstance(value, list):
        raise ValueError
    count = 0
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError
        merged_at = item.get("merged_at")
        if merged_at is not None and not isinstance(merged_at, str):
            raise ValueError
        count += merged_at is not None
    return count


def _release_presence(value: object) -> bool:
    if not isinstance(value, list):
        raise ValueError
    return bool(value)


def _actions_status(value: object) -> str | None:
    if not isinstance(value, Mapping):
        raise ValueError
    runs = value.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError
    if not runs:
        return None
    first = runs[0]
    if not isinstance(first, Mapping):
        raise ValueError
    status = first.get("conclusion") or first.get("status")
    if status is None:
        return None
    if not isinstance(status, str) or _ACTIONS_STATUS.fullmatch(status) is None:
        raise ValueError
    return status


def _contains_token(value: object, token: str) -> bool:
    if isinstance(value, str):
        return token in value
    if isinstance(value, Mapping):
        return any(
            _contains_token(key, token) or _contains_token(item, token)
            for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_token(item, token) for item in value)
    return False


@dataclass(slots=True, repr=False)
class GitHubGateway:
    """One-audit GitHub REST gateway with a detached secret-bearing boundary."""

    credentials: CredentialReader
    client: httpx.Client
    base_url: str = "https://github.com"
    timeout_seconds: float = 10.0
    _host: str = field(init=False, repr=False)
    _api_url: str = field(init=False, repr=False)
    _deadline: float | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.base_url)
            host = normalize_host(parsed.hostname or "")
            port = parsed.port
        except (UsageFailure, ValueError):
            raise ValueError("GitHub base URL must use HTTPS") from None
        if (
            parsed.scheme.casefold() != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("GitHub base URL must use HTTPS")
        authority = host if port is None else f"{host}:{port}"
        self._host = host
        self._api_url = (
            "https://api.github.com"
            if host == "github.com" and port is None
            else f"https://{authority}/api/v3"
        )

    def __repr__(self) -> str:
        return f"GitHubGateway(host={self._host!r}, timeout_seconds={self.timeout_seconds!r})"

    @property
    def host(self) -> str:
        return self._host

    def _remaining_timeout(self) -> float:
        now = time.monotonic()
        if self._deadline is None:
            self._deadline = now + self.timeout_seconds
        return max(self._deadline - now, 0.0)

    def _raw_get(
        self,
        path: str,
        params: Mapping[str, str] | None,
        parser: Callable[[object], _T],
    ) -> tuple[_RequestStatus, _T | None]:
        """Return only safe status/data after the token-bearing frame has unwound."""
        status = _RequestStatus.REQUEST_FAILED
        result: _T | None = None
        token: str | None = None
        response: httpx.Response | None = None
        headers: dict[str, str] = {}
        try:
            token = self.credentials.get(self._host)
            if not token:
                status = _RequestStatus.ABSENT
            else:
                timeout = self._remaining_timeout()
                if timeout > 0:
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                    }
                    response = self.client.get(
                        f"{self._api_url}{path}",
                        params=params,
                        headers=headers,
                        timeout=timeout,
                    )
                    if 200 <= response.status_code < 300:
                        candidate = parser(response.json())
                        if not _contains_token(candidate, token):
                            result = candidate
                            status = _RequestStatus.OK
        except Exception:
            status = _RequestStatus.REQUEST_FAILED
            result = None
        finally:
            token = None
            response = None
            headers = {}
        return (status, result)

    def _get(
        self,
        owner: str,
        repo: str,
        suffix: str,
        params: Mapping[str, str] | None,
        parser: Callable[[object], _T],
    ) -> _T:
        coordinates = safe_repository_coordinates(owner, repo)
        if coordinates is None:
            raise GitHubRequestError() from None
        safe_owner, safe_repo = coordinates
        status, result = self._raw_get(
            f"/repos/{safe_owner}/{safe_repo}{suffix}", params, parser
        )
        if status is _RequestStatus.ABSENT:
            raise GitHubTokenMissing() from None
        if status is not _RequestStatus.OK:
            raise GitHubRequestError() from None
        return cast(_T, result)

    def repository(self, owner: str, repo: str) -> dict[str, object]:
        return self._get(owner, repo, "", None, _repository_payload)

    def merged_pull_request_count(self, owner: str, repo: str) -> int:
        return self._get(
            owner,
            repo,
            "/pulls",
            {"state": "closed", "per_page": "100"},
            _pull_request_count,
        )

    def has_release(self, owner: str, repo: str) -> bool:
        return self._get(
            owner,
            repo,
            "/releases",
            {"per_page": "1"},
            _release_presence,
        )

    def latest_actions_status(self, owner: str, repo: str) -> str | None:
        return self._get(
            owner,
            repo,
            "/actions/runs",
            {"per_page": "1"},
            _actions_status,
        )

    def close(self) -> None:
        self.client.close()
