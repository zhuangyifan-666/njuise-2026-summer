import httpx
import pytest

from repoproof.github import GitHubGateway, GitHubRequestError


class FakeCredentials:
    def __init__(self, token: str | None) -> None:
        self.token = token

    def get(self, host: str) -> str | None:
        del host
        return self.token


class _ChunkedBody(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...], chunks_read: list[int]) -> None:
        self.chunks = chunks
        self.chunks_read = chunks_read

    def __iter__(self):
        for number, chunk in enumerate(self.chunks, start=1):
            self.chunks_read.append(number)
            yield chunk


def test_gateway_rejects_non_https_base_url() -> None:
    """Catches remote configuration that permits plaintext credential transport."""
    with pytest.raises(ValueError, match="HTTPS"):
        GitHubGateway(FakeCredentials("secret"), httpx.Client(), "http://github.com")


def test_gateway_sends_token_only_in_authorization_header() -> None:
    """Catches credentials entering a URL, gateway representation, or non-auth field."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"default_branch": "main"}, request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gateway = GitHubGateway(FakeCredentials("canary-token"), client)

    assert gateway.repository("owner", "repo") == {"default_branch": "main"}
    assert seen[0].headers["Authorization"] == "Bearer canary-token"
    assert "canary-token" not in str(seen[0].url)
    assert "canary-token" not in repr(gateway)
    gateway.close()


def test_gateway_stops_streaming_when_response_exceeds_its_byte_ceiling() -> None:
    """Catches eager or unbounded buffering of attacker-controlled remote responses."""
    chunks_read: list[int] = []
    chunks = (
        b"{" + b" " * (600 * 1024),
        b" " * (600 * 1024),
        b'"default_branch":"main"}',
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=_ChunkedBody(chunks, chunks_read),
            request=request,
        )

    gateway = GitHubGateway(
        FakeCredentials("canary-token"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(GitHubRequestError):
        gateway.repository("owner", "repo")

    assert chunks_read == [1, 2]
    gateway.close()


def test_explicit_default_github_port_uses_public_api_origin() -> None:
    """Catches github.com:443 being misrouted to the enterprise API path."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"default_branch": "main"}, request=request)

    gateway = GitHubGateway(
        FakeCredentials("canary-token"),
        httpx.Client(transport=httpx.MockTransport(handler)),
        "https://github.com:443",
    )

    assert gateway.repository("owner", "repo") == {"default_branch": "main"}
    assert str(seen[0].url) == "https://api.github.com/repos/owner/repo"
    gateway.close()


def test_unauthorized_error_detaches_token_bearing_httpx_objects() -> None:
    """Catches 401 request/response objects surviving in public exception state."""
    canary = "github_pat_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={"X-Private": canary},
            text=f"rejected {canary}",
            request=request,
        )

    gateway = GitHubGateway(
        FakeCredentials(canary),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(GitHubRequestError) as caught:
        gateway.repository("owner", "repo")

    error = caught.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert canary not in str(error)
    assert canary not in repr(error)
    traceback = error.__traceback__
    while traceback is not None:
        module = str(traceback.tb_frame.f_globals.get("__name__", ""))
        if module.startswith("repoproof"):
            for value in traceback.tb_frame.f_locals.values():
                assert canary not in repr(value)
        traceback = traceback.tb_next
    gateway.close()
