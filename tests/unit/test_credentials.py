import traceback

import pytest

from repoproof.credentials import CredentialStore, normalize_host
from repoproof.errors import UsageFailure


class FakeKeyring:
    priority = 1

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, account: str, value: str) -> None:
        self.values[(service, account)] = value

    def get_password(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def delete_password(self, service: str, account: str) -> None:
        self.values.pop((service, account), None)


class FailingKeyring(FakeKeyring):
    def set_password(self, service: str, account: str, value: str) -> None:
        raise RuntimeError(f"backend retained {value}")


def _traceback_contains(exception: BaseException, marker: str) -> bool:
    trace = exception.__traceback__
    while trace is not None:
        filename = trace.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/repoproof/" in filename and any(
            marker in repr(value) for value in trace.tb_frame.f_locals.values()
        ):
            return True
        trace = trace.tb_next
    detail = traceback.TracebackException.from_exception(exception, capture_locals=True)
    return any(
        "/src/repoproof/" in frame.filename.replace("\\", "/") and marker in repr(frame.locals)
        for frame in detail.stack
    )


def test_login_update_status_logout_lifecycle() -> None:
    """Catches storage that cannot update, report, and idempotently clear a credential."""
    backend = FakeKeyring()
    store = CredentialStore(backend)

    store.login("GitHub.COM.", "first-secret")
    assert store.configured("github.com") is True
    store.login("github.com", "second-secret")
    assert store.get("github.com") == "second-secret"
    store.logout("github.com")
    store.logout("github.com")

    assert store.configured("github.com") is False
    assert "second-secret" not in repr(store)

    token = "keyring-traceback-canary"
    with pytest.raises(UsageFailure) as error:
        CredentialStore(FailingKeyring()).login("github.com", token)

    assert token not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert not _traceback_contains(error.value, token)


def test_host_rejects_scheme_path_and_port() -> None:
    """Catches host normalization that accepts a URL or endpoint instead of a hostname."""
    for value in ("https://github.com", "github.com/path", "github.com:443"):
        with pytest.raises(UsageFailure, match="host"):
            normalize_host(value)
