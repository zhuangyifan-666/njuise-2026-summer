from pathlib import Path

from repoproof.collectors.base import AuditContext
from repoproof.collectors.github import GitHubCollector
from repoproof.domain import EvidenceState
from repoproof.profile.loader import load_profile


class FakeGateway:
    def __init__(self) -> None:
        self.close_calls = 0

    def repository(self, owner: str, repo: str) -> dict[str, object]:
        assert (owner, repo) == ("owner", "repo")
        return {"default_branch": "main"}

    def merged_pull_request_count(self, owner: str, repo: str) -> int:
        assert (owner, repo) == ("owner", "repo")
        return 2

    def has_release(self, owner: str, repo: str) -> bool:
        assert (owner, repo) == ("owner", "repo")
        return True

    def latest_actions_status(self, owner: str, repo: str) -> str:
        assert (owner, repo) == ("owner", "repo")
        return "success"

    def close(self) -> None:
        self.close_calls += 1


def test_collector_returns_only_structured_remote_facts_and_closes(tmp_path: Path) -> None:
    """Catches raw remote payload retention or an unclosed gateway."""
    gateway = FakeGateway()

    evidence = GitHubCollector(gateway, "owner/repo").collect(
        AuditContext(tmp_path, False), load_profile("ai4se-b")
    )[0]

    assert evidence.state is EvidenceState.AVAILABLE
    assert evidence.facts == {
        "default_branch": "main",
        "merged_pull_requests": 2,
        "has_release": True,
        "latest_actions_status": "success",
        "runtime_error": False,
    }
    assert gateway.close_calls == 1
