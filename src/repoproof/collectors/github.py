"""Optional structured GitHub repository evidence."""

from typing import Protocol

from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.github import (
    GitHubRequestError,
    GitHubTokenMissing,
    safe_repository_coordinates,
)
from repoproof.profile.models import Profile


class GitHubEvidenceGateway(Protocol):
    def repository(self, owner: str, repo: str) -> dict[str, object]: ...

    def merged_pull_request_count(self, owner: str, repo: str) -> int: ...

    def has_release(self, owner: str, repo: str) -> bool: ...

    def latest_actions_status(self, owner: str, repo: str) -> str | None: ...

    def close(self) -> None: ...


def _unavailable(
    context: AuditContext, reason: str, *, runtime_error: bool
) -> tuple[Evidence, ...]:
    return (
        Evidence(
            "github:repository",
            "github_repository",
            ".",
            EvidenceState.UNAVAILABLE,
            {"reason": reason, "runtime_error": runtime_error},
            collector_provenance(context, "github"),
        ),
    )


def _close_safely(gateway: GitHubEvidenceGateway) -> None:
    try:
        gateway.close()
    except Exception:
        return


class GitHubCollector:
    name = "github"

    def __init__(self, gateway: GitHubEvidenceGateway, slug: str | None) -> None:
        self.gateway = gateway
        self.slug = slug

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        del profile
        try:
            if context.offline:
                return _unavailable(context, "offline", runtime_error=False)
            parts = self.slug.split("/", 1) if isinstance(self.slug, str) else ()
            coordinates = (
                safe_repository_coordinates(parts[0], parts[1]) if len(parts) == 2 else None
            )
            if coordinates is None:
                return _unavailable(context, "origin_missing_or_invalid", runtime_error=False)
            owner, repo = coordinates
            repository = self.gateway.repository(owner, repo)
            facts: dict[str, object] = {
                "default_branch": repository["default_branch"],
                "merged_pull_requests": self.gateway.merged_pull_request_count(owner, repo),
                "has_release": self.gateway.has_release(owner, repo),
                "latest_actions_status": self.gateway.latest_actions_status(owner, repo),
                "runtime_error": False,
            }
            return (
                Evidence(
                    "github:repository",
                    "github_repository",
                    ".",
                    EvidenceState.AVAILABLE,
                    facts,
                    collector_provenance(context, self.name),
                ),
            )
        except GitHubTokenMissing:
            return _unavailable(context, "token_missing", runtime_error=False)
        except (GitHubRequestError, KeyError, TypeError, ValueError):
            return _unavailable(context, "network_auth_or_response_error", runtime_error=True)
        except Exception:
            return _unavailable(context, "remote_error", runtime_error=True)
        finally:
            _close_safely(self.gateway)
