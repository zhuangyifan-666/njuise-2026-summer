import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from repoproof.domain import Severity

RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")]


def _safe_repo_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("repository path must be a non-empty string")
    normalized = value.replace("\\", "/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized)
        or ".." in PurePosixPath(normalized).parts
    ):
        raise ValueError("repository path must be relative and contain no '..'")
    return normalized


SafeRepoPath = Annotated[str, BeforeValidator(_safe_repo_path)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PathExistsParams(StrictModel):
    paths: tuple[SafeRepoPath, ...] = Field(min_length=1)
    min_matches: int = Field(default=1, ge=1)


class MarkdownSectionsParams(StrictModel):
    path: SafeRepoPath
    headings: tuple[str, ...] = ()
    aliases: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    completed_items_require_commit: bool = False


class CIJobExistsParams(StrictModel):
    ci: Literal["gitlab", "github"]
    path: SafeRepoPath
    job: str


class GitHistoryParams(StrictModel):
    min_commits: int = Field(ge=0)
    require_non_default_branch: bool = False
    accept_local_merge: bool = True
    accept_remote_pr: bool = False


class DistributionReadyParams(StrictModel):
    allowed: tuple[Literal["python", "docker", "npm", "cargo"], ...]
    required_paths: tuple[SafeRepoPath, ...] = ()
    require_release_workflow: bool = True
    accept_published_release: bool = True


class SecretScanParams(StrictModel):
    categories: tuple[
        Literal["token", "private_key", "high_entropy", "sensitive_file"], ...
    ]
    entropy_threshold: float = Field(default=4.0, ge=3.0, le=8.0)
    exclude_paths: tuple[SafeRepoPath, ...] = ()


class RuleBase(StrictModel):
    id: RuleId
    severity: Severity
    remediation: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)
    ]


class PathExistsRule(RuleBase):
    type: Literal["path_exists"]
    params: PathExistsParams


class MarkdownSectionsRule(RuleBase):
    type: Literal["markdown_sections"]
    params: MarkdownSectionsParams


class CIJobExistsRule(RuleBase):
    type: Literal["ci_job_exists"]
    params: CIJobExistsParams


class GitHistoryRule(RuleBase):
    type: Literal["git_history"]
    params: GitHistoryParams


class DistributionReadyRule(RuleBase):
    type: Literal["distribution_ready"]
    params: DistributionReadyParams


class SecretScanRule(RuleBase):
    type: Literal["secret_scan"]
    params: SecretScanParams


Rule = Annotated[
    PathExistsRule
    | MarkdownSectionsRule
    | CIJobExistsRule
    | GitHistoryRule
    | DistributionReadyRule
    | SecretScanRule,
    Field(discriminator="type"),
]


class Profile(StrictModel):
    profile_schema: Literal[1] = Field(alias="schema", serialization_alias="schema")
    name: Annotated[str, StringConstraints(min_length=3, max_length=64)]
    description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    manual_checks: tuple[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)],
        ...,
    ] = ()
    rules: tuple[Rule, ...] = Field(min_length=1)

    @property
    def schema(self) -> Literal[1]:  # type: ignore[override]
        return self.profile_schema

    @model_validator(mode="after")
    def unique_rule_ids(self) -> "Profile":
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule id")
        return self
