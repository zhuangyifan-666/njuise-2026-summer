from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from repoproof.errors import UsageFailure

SERVICE: Final = "repoproof.github"
_HOST_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


class KeyringBackend(Protocol):
    def set_password(self, service: str, account: str, value: str) -> None: ...

    def get_password(self, service: str, account: str) -> str | None: ...

    def delete_password(self, service: str, account: str) -> None: ...


class _StoreStatus(StrEnum):
    OK = "ok"
    INVALID_HOST = "invalid_host"
    EMPTY_TOKEN = "empty_token"
    UNAVAILABLE = "unavailable"
    DELETE_FAILED = "delete_failed"


def _invalid_host() -> UsageFailure:
    return UsageFailure(
        "GitHub host is invalid.",
        "Pass a hostname such as github.com without scheme, port, or path.",
    )


def normalize_host(host: str) -> str:
    """Return a canonical DNS hostname, never a URL or endpoint."""
    if not isinstance(host, str):
        raise _invalid_host()
    normalized = host.strip().casefold().rstrip(".")
    labels = normalized.split(".")
    if (
        not normalized
        or len(normalized) > 253
        or any(
            not label
            or len(label) > 63
            or label[0] == "-"
            or label[-1] == "-"
            or any(character not in _HOST_CHARS for character in label)
            for label in labels
        )
    ):
        raise _invalid_host()
    return normalized


def _store_status(backend: KeyringBackend, host: str, token: str) -> _StoreStatus:
    """Contain token-bearing backend exceptions before any public failure is raised."""
    try:
        normalized = normalize_host(host)
        if not isinstance(token, str) or not token.strip():
            return _StoreStatus.EMPTY_TOKEN
        backend.set_password(SERVICE, normalized, token)
    except UsageFailure:
        return _StoreStatus.INVALID_HOST
    except Exception:
        return _StoreStatus.UNAVAILABLE
    finally:
        token = ""
    return _StoreStatus.OK


def _read_status(backend: KeyringBackend, host: str) -> tuple[_StoreStatus, str | None]:
    """Contain backend exceptions, which may include a stored credential in their message."""
    try:
        normalized = normalize_host(host)
        token = backend.get_password(SERVICE, normalized)
        return (_StoreStatus.OK, token)
    except UsageFailure:
        return (_StoreStatus.INVALID_HOST, None)
    except Exception:
        return (_StoreStatus.UNAVAILABLE, None)


def _configured_status(backend: KeyringBackend, host: str) -> tuple[_StoreStatus, bool]:
    status, token = _read_status(backend, host)
    configured = token is not None
    token = None
    return (status, configured)


def _delete_status(backend: KeyringBackend, host: str) -> _StoreStatus:
    try:
        normalized = normalize_host(host)
        backend.delete_password(SERVICE, normalized)
    except UsageFailure:
        return _StoreStatus.INVALID_HOST
    except Exception:
        return _StoreStatus.DELETE_FAILED
    return _StoreStatus.OK


def _failure_for(status: _StoreStatus) -> UsageFailure:
    if status is _StoreStatus.INVALID_HOST:
        return _invalid_host()
    if status is _StoreStatus.EMPTY_TOKEN:
        return UsageFailure("Token cannot be empty.", "Enter a non-empty token interactively.")
    if status is _StoreStatus.DELETE_FAILED:
        return UsageFailure("Credential could not be deleted.", "Check the OS keyring backend.")
    return UsageFailure(
        "System keyring is unavailable.",
        "Enable an OS keyring backend; plaintext fallback is disabled.",
    )


@dataclass(slots=True)
class CredentialStore:
    """Credential lifecycle facade that stores values exclusively in the operating-system keyring."""

    backend: KeyringBackend

    def __repr__(self) -> str:
        return f"CredentialStore(backend={self.backend_name()})"

    def login(self, host: str, token: str) -> None:
        status = _store_status(self.backend, host, token)
        token = ""
        if status is not _StoreStatus.OK:
            raise _failure_for(status)

    def get(self, host: str) -> str | None:
        status, token = _read_status(self.backend, host)
        if status is not _StoreStatus.OK:
            token = None
            raise _failure_for(status)
        return token

    def configured(self, host: str) -> bool:
        status, configured = _configured_status(self.backend, host)
        if status is not _StoreStatus.OK:
            raise _failure_for(status)
        return configured

    def logout(self, host: str) -> None:
        status, configured = _configured_status(self.backend, host)
        if status is not _StoreStatus.OK:
            raise _failure_for(status)
        if not configured:
            return
        status = _delete_status(self.backend, host)
        if status is not _StoreStatus.OK:
            raise _failure_for(status)

    def backend_name(self) -> str:
        return type(self.backend).__name__
