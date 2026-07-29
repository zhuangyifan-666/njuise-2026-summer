# RepoProof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and release RepoProof 1.0, an offline-first, read-only repository audit CLI with deterministic policy evaluation, safe credential handling, three report formats, CI evidence, and a downloadable Windows x64 executable.

**Architecture:** A Typer CLI calls an application service that loads a strict declarative profile, runs only the collectors required by that profile, evaluates structured evidence with a pure rule engine, and renders one immutable `AuditReport`. Domain models and the engine do not depend on the filesystem, Typer, HTTPX, keyring, or Rich; those details stay behind collector, reporter, credential-store, and transport boundaries.

**Tech Stack:** Python 3.12/3.13, Typer, Pydantic 2, PyYAML, Rich, markdown-it-py, pathspec, keyring, HTTPX, pytest, Hypothesis, Ruff, mypy, PyInstaller, GitHub Actions, and GitLab CI.

## Global Constraints

- The only supported rule types in schema 1 are `path_exists`, `markdown_sections`, `ci_job_exists`, `git_history`, `distribution_ready`, and `secret_scan`.
- Rule states are exactly `PASS`, `WARN`, `FAIL`, and `SKIP`; process exit codes are exactly 0 (no FAIL), 1 (completed with FAIL), 2 (CLI/profile error), and 3 (repository, network, or internal runtime error).
- The offline core must not call an LLM, require a network, require a Token, upload repository content, execute profile code, or modify the audited repository.
- Profile YAML uses safe parsing, strict models, a 1 MiB input limit, at most 50 aliases, and no unknown fields.
- Repository paths are normalized under the repository root; external symlinks, junctions, absolute profile paths, and `..` traversal are rejected or skipped without reading external content.
- Candidate limits are 20,000 files, 500 MiB total, and 2 MiB per readable file; Git commands and GitHub requests default to 10-second timeouts.
- Secret values and GitHub Tokens must never appear in stdout, stderr, logs, exceptions, snapshots, JSON, or HTML; only category, relative location, line number, and SHA-256 first 8 hexadecimal characters may be reported for a suspected secret.
- Tokens are accepted only through hidden interactive input and stored only as keyring service `repoproof.github`, account `<host>`; there is no plaintext fallback or `.env` loading.
- JSON and HTML writes use a temporary sibling file followed by `os.replace`; HTML is a self-contained, escaped document with no JavaScript or external resource.
- The release target is an unsigned Windows 10/11 x64 single executable plus SHA-256 checksum; README must explain SmartScreen, checksum verification, and source installation.
- Python 3.12 and 3.13 must pass tests; a `windows-latest` job must smoke-test the packaged executable.
- The performance acceptance target is an offline audit of 10,000 candidate files and at most 500 MiB in 15 seconds on the documented four-core benchmark environment.
- Every production change follows Red → Green → Refactor and ends in a focused commit. A task is not complete until its listed focused tests and the current full suite pass.

---

## Scope and dependency order

This is one cohesive product plan rather than separate subsystem plans because every later deliverable consumes the same schema-1 profile, domain types, evidence contract, and exit semantics. Each task below still produces a separately testable increment and has its own review gate.

```text
domain + toolchain
  └─ profile schema
      ├─ secure filesystem collectors
      ├─ Git collector
      ├─ secret collector
      └─ optional GitHub evidence
           └─ pure rule engine
                └─ report model/renderers
                     └─ application service + CLI
                          └─ fixtures, CI, packaging, documentation, Release
```

## Locked file map

### Packaging and entry points

- `pyproject.toml` — dependencies, `repoproof` console script, pytest/Ruff/mypy/PyInstaller configuration.
- `Makefile` — one-command `install`, `lint`, `typecheck`, `test`, and `verify` targets.
- `src/repoproof/__init__.py` — package version.
- `src/repoproof/__main__.py` — `python -m repoproof` entry point.
- `src/repoproof/cli.py` — Typer command tree and exception-to-exit-code boundary.
- `src/repoproof/app.py` — audit orchestration and dependency injection.

### Domain, profiles, rules

- `src/repoproof/domain.py` — dependency-free enums and immutable domain dataclasses.
- `src/repoproof/errors.py` — sanitized `UsageFailure` and `RuntimeFailure`.
- `src/repoproof/profile/models.py` — strict Pydantic schema-1 rule models.
- `src/repoproof/profile/loader.py` — bounded safe YAML loading and built-in lookup.
- `src/repoproof/profile/builtin/ai4se-b.yml` — bundled course policy.
- `src/repoproof/rules.py` — pure evaluation registry and six rule evaluators.

### Collectors and boundaries

- `src/repoproof/security.py` — root containment, redaction, and secret fingerprint helpers.
- `src/repoproof/collectors/base.py` — `AuditContext`, `Collector` protocol, evidence utilities.
- `src/repoproof/collectors/files.py` — bounded ignore-aware path inventory.
- `src/repoproof/collectors/markdown.py` — bounded Markdown heading/checklist evidence.
- `src/repoproof/collectors/ci.py` — safe static GitLab/GitHub Actions YAML evidence.
- `src/repoproof/collectors/distribution.py` — packaging and release-workflow evidence.
- `src/repoproof/collectors/git.py` — shell-free, bounded Git CLI adapter.
- `src/repoproof/collectors/secrets.py` — streaming secret patterns, entropy, allowlist, and redacted evidence.
- `src/repoproof/collectors/github.py` — optional remote release/PR/Actions evidence.
- `src/repoproof/github.py` — HTTPS-only GitHub REST gateway with injected HTTPX transport.
- `src/repoproof/credentials.py` — injected keyring credential lifecycle.

### Reports

- `src/repoproof/reporting/model.py` — deterministic conversion from domain objects to schema-1 primitives.
- `src/repoproof/reporting/console.py` — Rich/plain terminal rendering.
- `src/repoproof/reporting/json_reporter.py` — UTF-8 schema-1 JSON.
- `src/repoproof/reporting/html_reporter.py` — escaped, self-contained HTML.
- `src/repoproof/reporting/output.py` — atomic output routing.

### Tests and delivery

- `tests/unit/` — pure model, profile, rule, security, and reporter tests.
- `tests/integration/` — temporary filesystem, Git, keyring, HTTP transport, and CLI tests.
- `tests/e2e/` — compliant/noncompliant fixture audits and semantic report parity.
- `tests/performance/` — the documented 10,000-file benchmark.
- `examples/compliant-repo/` and `examples/noncompliant-repo/` — deterministic public fixtures.
- `.github/workflows/ci.yml` — Python 3.12/3.13 test, lint, and type-check matrix.
- `.github/workflows/release.yml` — tagged Windows build, smoke test, checksum, and GitHub Release.
- `.gitlab-ci.yml` — course-required `unit-test` job.
- `repoproof.spec` — deterministic PyInstaller entry point.
- `README.md`, `REFLECTION.md`, `PLAN.md`, `AGENT_LOG.md`, `SPEC_PROCESS.md` — user and process deliverables.

## Stable interfaces shared by tasks

```python
# src/repoproof/domain.py
class FindingStatus(str, Enum): PASS = "PASS"; WARN = "WARN"; FAIL = "FAIL"; SKIP = "SKIP"
class Severity(str, Enum): ERROR = "error"; WARNING = "warning"
class EvidenceState(str, Enum): AVAILABLE = "available"; UNAVAILABLE = "unavailable"; LIMITED = "limited"
class ExitCode(IntEnum): OK = 0; FINDINGS = 1; USAGE = 2; RUNTIME = 3

@dataclass(frozen=True, slots=True)
class Location:
    path: str
    line: int | None = None

@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    subject: str
    state: EvidenceState
    facts: Mapping[str, object]
    provenance: Mapping[str, object]

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    status: FindingStatus
    severity: Severity
    message: str
    locations: tuple[Location, ...]
    evidence_ids: tuple[str, ...]
    remediation: str

@dataclass(frozen=True, slots=True)
class AuditReport:
    report_schema: int
    tool_version: str
    generated_at: datetime
    repository_name: str
    profile_name: str
    profile_schema: int
    profile_hash: str
    findings: tuple[Finding, ...]
    manual_checks: tuple[str, ...]
    diagnostics: tuple[str, ...]
    timings_ms: Mapping[str, int]
    exit_code: ExitCode
```

```python
# src/repoproof/collectors/base.py
@dataclass(frozen=True, slots=True)
class AuditContext:
    root: Path
    offline: bool
    max_files: int = 20_000
    max_total_bytes: int = 500 * 1024 * 1024
    max_read_bytes: int = 2 * 1024 * 1024
    timeout_seconds: float = 10.0
    snapshot_at: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)

class Collector(Protocol):
    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]: ...
```

```python
# public functions consumed across tasks
def load_profile(name_or_path: str) -> Profile: ...
def required_collector_names(profile: Profile, offline: bool) -> tuple[str, ...]: ...
def evaluate(profile: Profile, evidence: Sequence[Evidence]) -> tuple[Finding, ...]: ...
def build_report(profile: Profile, root: Path, findings: Sequence[Finding],
                 diagnostics: Sequence[str], timings_ms: Mapping[str, int],
                 generated_at: datetime, runtime_failed: bool = False) -> AuditReport: ...
def report_to_dict(report: AuditReport) -> dict[str, object]: ...
def run_audit(request: AuditRequest, dependencies: AppDependencies) -> AuditReport: ...
```

---

### Task 1: Establish the tested package, domain contract, and version command

**Files:**
- Create: `pyproject.toml`
- Create: `Makefile`
- Create: `src/repoproof/__init__.py`
- Create: `src/repoproof/__main__.py`
- Create: `src/repoproof/domain.py`
- Create: `src/repoproof/errors.py`
- Create: `src/repoproof/cli.py`
- Create: `tests/unit/test_domain.py`
- Create: `tests/integration/test_cli_version.py`

**Interfaces:**
- Consumes: no product code.
- Produces: every enum/dataclass in “Stable interfaces”; `UsageFailure(message, remediation)`; `RuntimeFailure(message, remediation)`; Typer `app`; `repoproof version`.

- [ ] **Step 1: Write failing domain and CLI tests**

```python
# tests/unit/test_domain.py
from repoproof.domain import ExitCode, FindingStatus, Severity, status_for_failure

def test_error_rule_failure_is_fail() -> None:
    assert status_for_failure(Severity.ERROR) is FindingStatus.FAIL

def test_warning_rule_failure_is_warn() -> None:
    assert status_for_failure(Severity.WARNING) is FindingStatus.WARN

def test_exit_codes_are_stable() -> None:
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3]
```

```python
# tests/integration/test_cli_version.py
from typer.testing import CliRunner
from repoproof.cli import app

def test_version_prints_semver_without_ansi() -> None:
    result = CliRunner().invoke(app, ["version"], color=False)
    assert result.exit_code == 0
    assert result.stdout == "repoproof 0.1.0\n"
    assert "\x1b[" not in result.stdout
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m pytest tests/unit/test_domain.py tests/integration/test_cli_version.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'repoproof'`.

- [ ] **Step 3: Add package metadata and minimal domain/CLI implementation**

```toml
# pyproject.toml
[build-system]
requires = ["hatchling>=1.25,<2"]
build-backend = "hatchling.build"

[project]
name = "repoproof"
version = "0.1.0"
description = "Deterministic offline-first repository release-readiness auditor"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
  "httpx>=0.27,<1",
  "keyring>=25,<26",
  "markdown-it-py>=3,<4",
  "pathspec>=0.12,<1",
  "pydantic>=2.8,<3",
  "PyYAML>=6.0.2,<7",
  "rich>=13.7,<14",
  "typer>=0.12,<1",
]

[project.optional-dependencies]
dev = [
  "hypothesis>=6.108,<7",
  "mypy>=1.11,<2",
  "pyinstaller>=6.10,<7",
  "pytest>=8.3,<9",
  "pytest-cov>=5,<6",
  "ruff>=0.6,<1",
  "types-PyYAML>=6.0.12,<7",
]

[project.scripts]
repoproof = "repoproof.cli:app"

[tool.hatch.build.targets.wheel]
packages = ["src/repoproof"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers --strict-config"

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S"]

[tool.ruff.lint.per-file-ignores]
"src/repoproof/cli.py" = ["B008"]
"src/repoproof/collectors/git.py" = ["S603", "S607"]
"tests/**/*.py" = ["S101", "S105", "S106", "S603", "S607"]

[tool.mypy]
python_version = "3.12"
strict = true
packages = ["repoproof"]
```

```python
# src/repoproof/domain.py
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from typing import Mapping

class FindingStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"

class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"

class EvidenceState(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    LIMITED = "limited"

class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    USAGE = 2
    RUNTIME = 3

def status_for_failure(severity: Severity) -> FindingStatus:
    return FindingStatus.FAIL if severity is Severity.ERROR else FindingStatus.WARN

@dataclass(frozen=True, slots=True)
class Location:
    path: str
    line: int | None = None

@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    subject: str
    state: EvidenceState
    facts: Mapping[str, object]
    provenance: Mapping[str, object]

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    status: FindingStatus
    severity: Severity
    message: str
    locations: tuple[Location, ...]
    evidence_ids: tuple[str, ...]
    remediation: str

@dataclass(frozen=True, slots=True)
class AuditReport:
    report_schema: int
    tool_version: str
    generated_at: datetime
    repository_name: str
    profile_name: str
    profile_schema: int
    profile_hash: str
    findings: tuple[Finding, ...]
    manual_checks: tuple[str, ...]
    diagnostics: tuple[str, ...]
    timings_ms: Mapping[str, int]
    exit_code: ExitCode
```

```python
# src/repoproof/errors.py
class RepoProofFailure(Exception):
    def __init__(self, message: str, remediation: str) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation

class UsageFailure(RepoProofFailure):
    pass

class RuntimeFailure(RepoProofFailure):
    pass
```

```python
# src/repoproof/__init__.py
__version__ = "0.1.0"
```

```python
# src/repoproof/cli.py
import typer
from repoproof import __version__

app = typer.Typer(no_args_is_help=True, help="Audit repository release readiness.")

@app.command()
def version() -> None:
    """Print the installed RepoProof version."""
    typer.echo(f"repoproof {__version__}")
```

```python
# src/repoproof/__main__.py
from repoproof.cli import app

if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Add the unified local commands**

```make
# Makefile
.PHONY: install lint typecheck test verify
install:
	python -m pip install -e ".[dev]"
lint:
	python -m ruff check src tests
typecheck:
	python -m mypy src
test:
	python -m pytest
verify: lint typecheck test
```

- [ ] **Step 5: Verify GREEN and quality**

Run: `python -m pip install -e ".[dev]"`

Run: `python -m pytest tests/unit/test_domain.py tests/integration/test_cli_version.py -q`

Run: `python -m ruff check src tests && python -m mypy src`

Expected: all commands exit 0; focused pytest reports 4 passed.

- [ ] **Step 6: Commit the tested foundation**

```bash
git add pyproject.toml Makefile src/repoproof tests/unit/test_domain.py tests/integration/test_cli_version.py
git commit -m "build: establish RepoProof package and domain contract"
```

---

### Task 2: Implement strict profile schema and the bundled `ai4se-b` policy

**Files:**
- Create: `src/repoproof/profile/__init__.py`
- Create: `src/repoproof/profile/builtin/__init__.py`
- Create: `src/repoproof/profile/models.py`
- Create: `src/repoproof/profile/loader.py`
- Create: `src/repoproof/profile/builtin/ai4se-b.yml`
- Create: `tests/unit/profile/test_models.py`
- Create: `tests/unit/profile/test_loader.py`
- Create: `tests/integration/test_cli_profile.py`
- Modify: `src/repoproof/cli.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `UsageFailure`, `Severity`.
- Produces: strict `Profile`; discriminated `Rule`; `load_profile(name_or_path)`; `profile_hash(profile)`; `profile list`; `profile validate`.

- [ ] **Step 1: Write failing model and loader tests**

```python
# tests/unit/profile/test_models.py
import pytest
from pydantic import ValidationError
from repoproof.profile.models import Profile

BASE = {
    "schema": 1,
    "name": "team-policy",
    "description": "Team release checks",
    "rules": [{
        "id": "docs.spec",
        "type": "path_exists",
        "severity": "error",
        "params": {"paths": ["SPEC.md"], "min_matches": 1},
        "remediation": "Add SPEC.md.",
    }],
}

def test_profile_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Profile.model_validate(BASE | {"command": "rm -rf ."})

def test_profile_rejects_duplicate_rule_ids() -> None:
    duplicate = BASE | {"rules": [BASE["rules"][0], BASE["rules"][0]]}
    with pytest.raises(ValidationError, match="duplicate rule id"):
        Profile.model_validate(duplicate)

def test_profile_rejects_unknown_rule_type() -> None:
    invalid = BASE | {"rules": [BASE["rules"][0] | {"type": "python_eval"}]}
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        Profile.model_validate(invalid)

@pytest.mark.parametrize("path", ["../secret.txt", "/etc/passwd", r"C:\Users\secret.txt"])
def test_profile_rejects_unsafe_repository_paths(path: str) -> None:
    invalid = BASE | {"rules": [{
        **BASE["rules"][0],
        "params": {"paths": [path], "min_matches": 1},
    }]}
    with pytest.raises(ValidationError, match="relative"):
        Profile.model_validate(invalid)
```

```python
# tests/unit/profile/test_loader.py
from pathlib import Path
import pytest
from repoproof.errors import UsageFailure
from repoproof.profile.loader import load_profile, profile_hash

def test_builtin_profile_has_schema_one_and_six_rule_types() -> None:
    profile = load_profile("ai4se-b")
    assert profile.schema == 1
    assert {rule.type for rule in profile.rules} == {
        "path_exists", "markdown_sections", "ci_job_exists",
        "git_history", "distribution_ready", "secret_scan",
    }

def test_alias_limit_is_enforced(tmp_path: Path) -> None:
    aliases = "\n".join(f"  x{i}: *base" for i in range(51))
    policy = tmp_path / "aliases.yml"
    policy.write_text(f"schema: &base 1\nname: policy\ndescription: x\n{aliases}\nrules: []\n")
    with pytest.raises(UsageFailure, match="50 YAML aliases"):
        load_profile(str(policy))

def test_hash_is_stable_for_same_semantics(tmp_path: Path) -> None:
    first = load_profile("ai4se-b")
    second = load_profile("ai4se-b")
    assert profile_hash(first) == profile_hash(second)
```

```python
# tests/integration/test_cli_profile.py
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

def test_profile_list_contains_builtin() -> None:
    result = CliRunner().invoke(app, ["profile", "list"])
    assert result.exit_code == 0
    assert result.stdout == "ai4se-b\n"

def test_profile_validate_reports_yaml_path_and_exits_two(tmp_path: Path) -> None:
    policy = tmp_path / "invalid.yml"
    policy.write_text(
        "schema: 1\nname: abc\ndescription: test\nrules:\n"
        "  - id: bad.rule\n    type: path_exists\n    severity: error\n"
        "    params: {paths: [SPEC.md], unknown: true}\n"
        "    remediation: Add it.\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["profile", "validate", str(policy)])
    assert result.exit_code == 2
    assert "rules.0.path_exists.params.unknown" in result.stderr
```

- [ ] **Step 2: Run profile tests and verify RED**

Run: `python -m pytest tests/unit/profile -q`

Expected: collection fails because `repoproof.profile` does not exist.

- [ ] **Step 3: Implement strict discriminated models**

```python
# src/repoproof/profile/models.py
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal
from pydantic import (
    BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, model_validator,
)
from repoproof.domain import Severity

RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")]

def _safe_repo_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("repository path must be a non-empty string")
    normalized = value.replace("\\", "/")
    if (normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized) or
            ".." in PurePosixPath(normalized).parts):
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
    categories: tuple[Literal["token", "private_key", "high_entropy", "sensitive_file"], ...]
    entropy_threshold: float = Field(default=4.0, ge=3.0, le=8.0)
    exclude_paths: tuple[SafeRepoPath, ...] = ()

class RuleBase(StrictModel):
    id: RuleId
    severity: Severity
    remediation: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]

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
    PathExistsRule | MarkdownSectionsRule | CIJobExistsRule |
    GitHistoryRule | DistributionReadyRule | SecretScanRule,
    Field(discriminator="type"),
]

class Profile(StrictModel):
    schema: Literal[1]
    name: Annotated[str, StringConstraints(min_length=3, max_length=64)]
    description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    manual_checks: tuple[
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)], ...
    ] = ()
    rules: tuple[Rule, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_rule_ids(self) -> "Profile":
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule id")
        return self
```

- [ ] **Step 4: Implement bounded safe loading and stable hashing**

```python
# src/repoproof/profile/loader.py
import hashlib
import json
from importlib.resources import files
from pathlib import Path
import yaml
from yaml.tokens import AliasToken
from pydantic import ValidationError
from repoproof.errors import UsageFailure
from repoproof.profile.models import Profile

MAX_PROFILE_BYTES = 1024 * 1024
MAX_ALIASES = 50

def _read_profile(name_or_path: str) -> bytes:
    if name_or_path == "ai4se-b":
        return files("repoproof.profile.builtin").joinpath("ai4se-b.yml").read_bytes()
    path = Path(name_or_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UsageFailure("Profile could not be read.", "Check --profile path and permissions.") from exc
    if len(data) > MAX_PROFILE_BYTES:
        raise UsageFailure("Profile exceeds 1 MiB.", "Reduce the YAML profile size.")
    return data

def load_profile(name_or_path: str) -> Profile:
    data = _read_profile(name_or_path)
    try:
        text = data.decode("utf-8")
        aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
        if aliases > MAX_ALIASES:
            raise UsageFailure("Profile exceeds 50 YAML aliases.", "Remove YAML alias expansion.")
        raw = yaml.safe_load(text)
        return Profile.model_validate(raw)
    except UsageFailure:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise UsageFailure("Profile is invalid.", f"Correct the reported YAML/schema error: {exc}") from exc

def profile_hash(profile: Profile) -> str:
    canonical = json.dumps(profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
```

- [ ] **Step 5: Add the complete bundled policy and profile CLI**

```yaml
# src/repoproof/profile/builtin/ai4se-b.yml
schema: 1
name: ai4se-b
description: AI4SE B project release-readiness checks
manual_checks:
  - Review REFLECTION.md for concrete lessons and limitations.
  - Review whether module responsibilities are clear and cohesive.
  - Review whether Git history supports the claimed TDD and review process.
rules:
  - id: docs.required
    type: path_exists
    severity: error
    params:
      paths: [SPEC.md, PLAN.md, SPEC_PROCESS.md, README.md, AGENT_LOG.md, REFLECTION.md, .gitlab-ci.yml]
      min_matches: 7
    remediation: Add every required course document and GitLab CI file.
  - id: readme.sections
    type: markdown_sections
    severity: error
    params:
      path: README.md
      headings: [项目简介, 安装, 运行, 测试, 分发, 目录结构, 安全边界, 已知限制]
      aliases:
        项目简介: [Overview]
        安装: [Installation]
        运行: [Usage]
        测试: [Testing]
        分发: [Distribution]
        目录结构: [Project Structure]
        安全边界: [Security Boundary]
        已知限制: [Known Limitations]
    remediation: Add the required README sections.
  - id: plan.commit-evidence
    type: markdown_sections
    severity: warning
    params:
      path: PLAN.md
      completed_items_require_commit: true
    remediation: Add a 7-40 character Git commit hash to every completed PLAN checklist item.
  - id: ci.gitlab-unit-test
    type: ci_job_exists
    severity: error
    params: {ci: gitlab, path: .gitlab-ci.yml, job: unit-test}
    remediation: Add a top-level unit-test job to .gitlab-ci.yml.
  - id: ci.github
    type: path_exists
    severity: warning
    params: {paths: [.github/workflows/*.yml, .github/workflows/*.yaml], min_matches: 1}
    remediation: Add a GitHub Actions test workflow.
  - id: test.entry
    type: path_exists
    severity: error
    params: {paths: [Makefile, pyproject.toml, package.json, Cargo.toml], min_matches: 1}
    remediation: Add a one-command test entry point.
  - id: git.minimum-history
    type: git_history
    severity: error
    params: {min_commits: 5}
    remediation: Preserve at least five focused commits.
  - id: git.process-evidence
    type: git_history
    severity: warning
    params:
      min_commits: 1
      require_non_default_branch: true
      accept_local_merge: true
      accept_remote_pr: true
    remediation: Preserve a non-default branch plus local merge or remote pull request evidence.
  - id: distribution.windows-release
    type: distribution_ready
    severity: error
    params:
      allowed: [python]
      required_paths: [pyproject.toml, repoproof.spec]
      require_release_workflow: true
      accept_published_release: true
    remediation: Add packaging configuration and a Release workflow or published Release.
  - id: security.secrets
    type: secret_scan
    severity: error
    params:
      categories: [token, private_key, high_entropy, sensitive_file]
      entropy_threshold: 4.0
      exclude_paths: [.git/**, .venv/**, dist/**, build/**]
    remediation: Revoke and remove the suspected secret, then use a safe credential store.
```

Both `src/repoproof/profile/__init__.py` and `src/repoproof/profile/builtin/__init__.py` are empty
package markers. Add this package-data declaration so the built-in YAML is present in wheels:

```toml
[tool.hatch.build.targets.wheel.force-include]
"src/repoproof/profile/builtin/ai4se-b.yml" = "repoproof/profile/builtin/ai4se-b.yml"
```

```python
# addition to src/repoproof/cli.py
from pathlib import Path
from repoproof.errors import UsageFailure
from repoproof.profile.loader import load_profile

profile_app = typer.Typer(help="Inspect and validate audit profiles.")
app.add_typer(profile_app, name="profile")

@profile_app.command("list")
def profile_list() -> None:
    typer.echo("ai4se-b")

@profile_app.command("validate")
def profile_validate(profile_path: Path) -> None:
    try:
        profile = load_profile(str(profile_path))
    except UsageFailure as exc:
        typer.echo(f"profile: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"valid profile: {profile.name} (schema {profile.schema})")
```

- [ ] **Step 6: Verify profile behavior and commit**

Run: `python -m pytest tests/unit/profile tests/integration/test_cli_profile.py -q`

Run: `python -m ruff check src tests && python -m mypy src`

Expected: all commands exit 0; invalid profile CLI cases exit 2 and never scan a repository.

```bash
git add pyproject.toml src/repoproof/profile src/repoproof/cli.py tests/unit/profile tests/integration/test_cli_profile.py
git commit -m "feat: add strict profiles and AI4SE policy"
```

---

### Task 3: Enforce repository containment and collect a bounded file inventory

**Files:**
- Create: `src/repoproof/security.py`
- Create: `src/repoproof/collectors/__init__.py`
- Create: `src/repoproof/collectors/base.py`
- Create: `src/repoproof/collectors/files.py`
- Create: `tests/unit/test_security.py`
- Create: `tests/integration/collectors/test_files.py`

**Interfaces:**
- Consumes: `Profile`, `Evidence`, `EvidenceState`, `RuntimeFailure`.
- Produces: `resolve_under_root(root, candidate)`; `redact_text(text)`; `short_fingerprint(value)`; `AuditContext`; `FileCollector.collect(...)` with evidence kind `file_inventory`.

- [ ] **Step 1: Write failing traversal, symlink, ignore, and limit tests**

```python
# tests/unit/test_security.py
from pathlib import Path
import pytest
from repoproof.errors import UsageFailure
from repoproof.security import resolve_under_root

def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(UsageFailure, match="outside repository"):
        resolve_under_root(root, "../outside.txt")

def test_absolute_profile_path_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(UsageFailure, match="relative"):
        resolve_under_root(root, str((tmp_path / "secret").resolve()))
```

```python
# tests/integration/collectors/test_files.py
from pathlib import Path
import pytest
from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import FileCollector
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile

def test_inventory_respects_git_and_repoproof_ignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (tmp_path / ".repoproofignore").write_text("private/**\n", encoding="utf-8")
    (tmp_path / "kept.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("no", encoding="utf-8")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "hidden.txt").write_text("no", encoding="utf-8")
    evidence = FileCollector().collect(AuditContext(tmp_path, offline=True), load_profile("ai4se-b"))[0]
    assert evidence.facts["paths"] == (".gitignore", ".repoproofignore", "kept.txt")

def test_external_symlink_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("canary", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    evidence = FileCollector().collect(AuditContext(root, offline=True), load_profile("ai4se-b"))[0]
    assert "link.txt" not in evidence.facts["paths"]
    assert "canary" not in repr(evidence)

def test_candidate_limit_fails_closed(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeFailure, match="candidate file limit"):
        FileCollector().collect(AuditContext(tmp_path, offline=True, max_files=2), load_profile("ai4se-b"))
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/test_security.py tests/integration/collectors/test_files.py -q`

Expected: collection fails because security and collector modules do not exist.

- [ ] **Step 3: Implement path containment and the collector contract**

```python
# src/repoproof/security.py
import hashlib
from pathlib import Path
from repoproof.errors import UsageFailure

def resolve_under_root(root: Path, candidate: str) -> Path:
    relative = Path(candidate)
    if relative.is_absolute():
        raise UsageFailure("Profile paths must be relative.", "Use a repository-relative path.")
    if ".." in relative.parts:
        raise UsageFailure("Path traversal is not allowed.", "Remove every '..' path component.")
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / relative).resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise UsageFailure("Path resolves outside repository.", "Remove traversal or external links.") from exc
    return resolved

def short_fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]

def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    redacted = text
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    return redacted
```

```python
# src/repoproof/collectors/base.py
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from repoproof.domain import Evidence
from repoproof.profile.models import Profile

@dataclass(frozen=True, slots=True)
class AuditContext:
    root: Path
    offline: bool
    max_files: int = 20_000
    max_total_bytes: int = 500 * 1024 * 1024
    max_read_bytes: int = 2 * 1024 * 1024
    timeout_seconds: float = 10.0
    snapshot_at: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)

class Collector(Protocol):
    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]: ...

def collector_provenance(context: AuditContext, name: str,
                         **extra: object) -> dict[str, object]:
    return {
        "collector": name,
        "version": 1,
        "time": context.snapshot_at.isoformat().replace("+00:00", "Z"),
        **extra,
    }
```

- [ ] **Step 4: Implement ignore-aware bounded enumeration**

```python
# src/repoproof/collectors/files.py
from pathlib import Path
import pathspec
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.errors import RuntimeFailure
from repoproof.profile.models import Profile

DEFAULT_IGNORES = (".git/", ".venv/", "build/", "dist/", "__pycache__/")

def _ignore_spec(root: Path) -> pathspec.PathSpec:
    lines = list(DEFAULT_IGNORES)
    for name in (".gitignore", ".repoproofignore"):
        path = root / name
        if path.is_file() and path.stat().st_size <= 2 * 1024 * 1024:
            lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)

class FileCollector:
    name = "files"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        root = context.root.resolve(strict=True)
        ignores = _ignore_spec(root)
        paths: list[str] = []
        sizes: dict[str, int] = {}
        total = 0
        for candidate in root.rglob("*"):
            relative = candidate.relative_to(root).as_posix()
            if ignores.match_file(relative) or not candidate.is_file() or candidate.is_symlink():
                continue
            try:
                candidate.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                continue
            size = candidate.stat().st_size
            paths.append(relative)
            sizes[relative] = size
            total += size
            if len(paths) > context.max_files:
                raise RuntimeFailure("Repository exceeds candidate file limit.", "Reduce scope or ignored paths.")
            if total > context.max_total_bytes:
                raise RuntimeFailure("Repository exceeds total byte limit.", "Reduce scope or ignored paths.")
        ordered = tuple(sorted(paths))
        return (Evidence(
            id="files.inventory",
            kind="file_inventory",
            subject=".",
            state=EvidenceState.AVAILABLE,
            facts={"paths": ordered, "sizes": {path: sizes[path] for path in ordered}, "total_bytes": total},
            provenance=collector_provenance(context, self.name),
        ),)
```

- [ ] **Step 5: Verify GREEN, add a Windows junction case where privileges allow, and commit**

Run: `python -m pytest tests/unit/test_security.py tests/integration/collectors/test_files.py -q`

Run: `python -m pytest -q`

Expected: all tests pass; no evidence representation contains the external canary.

```bash
git add src/repoproof/security.py src/repoproof/collectors tests/unit/test_security.py tests/integration/collectors/test_files.py
git commit -m "feat: collect bounded repository file evidence"
```

---

### Task 4: Collect Markdown, CI, and distribution evidence without executing input

**Files:**
- Create: `src/repoproof/collectors/markdown.py`
- Create: `src/repoproof/collectors/ci.py`
- Create: `src/repoproof/collectors/distribution.py`
- Create: `tests/integration/collectors/test_markdown.py`
- Create: `tests/integration/collectors/test_ci.py`
- Create: `tests/integration/collectors/test_distribution.py`

**Interfaces:**
- Consumes: `AuditContext`, `Profile`, `resolve_under_root`.
- Produces: evidence kinds `markdown`, `ci_config`, and `distribution`; facts defined in this task and consumed by Task 7.

- [ ] **Step 1: Write failing collector tests**

```python
# tests/integration/collectors/test_markdown.py
from pathlib import Path
from repoproof.collectors.base import AuditContext
from repoproof.collectors.markdown import MarkdownCollector
from repoproof.profile.loader import load_profile

def test_atx_setext_and_completed_commit_evidence(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# 项目简介\n\n安装\n====\n", encoding="utf-8")
    (tmp_path / "PLAN.md").write_text("- [x] parser (`1a2b3c4`)\n- [ ] release\n", encoding="utf-8")
    evidence = MarkdownCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))
    by_subject = {item.subject: item for item in evidence}
    assert by_subject["README.md"].facts["headings"] == ("项目简介", "安装")
    assert by_subject["PLAN.md"].facts["completed_items"] == (
        {"line": 1, "has_commit": True},
    )
```

```python
# tests/integration/collectors/test_ci.py
from pathlib import Path
from repoproof.collectors.base import AuditContext
from repoproof.collectors.ci import CICollector
from repoproof.profile.loader import load_profile

def test_gitlab_jobs_exclude_reserved_keys(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(
        "stages: [test]\nunit-test:\n  script: [python -m pytest]\n", encoding="utf-8"
    )
    evidence = CICollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))
    assert evidence[0].facts["jobs"] == ("unit-test",)
    assert "stages" not in evidence[0].facts["jobs"]

def test_unsafe_yaml_tag_is_limited(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text("x: !!python/object/apply:os.system ['whoami']\n")
    evidence = CICollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))
    assert evidence[0].state.value == "limited"
```

```python
# tests/integration/collectors/test_distribution.py
from pathlib import Path
from repoproof.collectors.base import AuditContext
from repoproof.collectors.distribution import DistributionCollector
from repoproof.profile.loader import load_profile

def test_python_packaging_and_release_workflow_are_detected(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "repoproof.spec").write_text("a = Analysis([])\n")
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "release.yml").write_text("on:\n  push:\n    tags: ['v*']\n")
    evidence = DistributionCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    assert evidence.facts["packaging"] == ("python",)
    assert evidence.facts["release_workflow"] is True
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/integration/collectors/test_markdown.py tests/integration/collectors/test_ci.py tests/integration/collectors/test_distribution.py -q`

Expected: collection fails for the three missing collector modules.

- [ ] **Step 3: Implement bounded Markdown parsing**

```python
# src/repoproof/collectors/markdown.py
import re
from markdown_it import MarkdownIt
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import MarkdownSectionsRule, Profile
from repoproof.security import resolve_under_root

COMMIT_RE = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{7,40})(?![0-9a-f])", re.IGNORECASE)
CHECKED_RE = re.compile(r"^\s*[-*+]\s+\[[xX]\]\s+")

def _normalize_heading(value: str) -> str:
    return " ".join(value.casefold().split())

class MarkdownCollector:
    name = "markdown"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        subjects = sorted({rule.params.path for rule in profile.rules if isinstance(rule, MarkdownSectionsRule)})
        result: list[Evidence] = []
        for subject in subjects:
            path = resolve_under_root(context.root, subject)
            if not path.is_file():
                result.append(Evidence(f"markdown:{subject}", "markdown", subject,
                    EvidenceState.UNAVAILABLE, {}, collector_provenance(context, self.name)))
                continue
            if path.stat().st_size > context.max_read_bytes:
                result.append(Evidence(f"markdown:{subject}", "markdown", subject,
                    EvidenceState.LIMITED, {"reason": "file_too_large"},
                    collector_provenance(context, self.name)))
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                result.append(Evidence(f"markdown:{subject}", "markdown", subject,
                    EvidenceState.LIMITED, {"reason": "invalid_utf8"},
                    collector_provenance(context, self.name)))
                continue
            tokens = MarkdownIt().parse(text)
            headings = tuple(_normalize_heading(tokens[index + 1].content)
                for index, token in enumerate(tokens[:-1]) if token.type == "heading_open")
            completed = tuple(
                {"line": line_number, "has_commit": bool(COMMIT_RE.search(line))}
                for line_number, line in enumerate(text.splitlines(), start=1) if CHECKED_RE.match(line)
            )
            result.append(Evidence(f"markdown:{subject}", "markdown", subject,
                EvidenceState.AVAILABLE, {"headings": headings, "completed_items": completed},
                collector_provenance(context, self.name)))
        return tuple(result)
```

- [ ] **Step 4: Implement safe CI and static distribution parsing**

```python
# src/repoproof/collectors/ci.py
from pathlib import Path
import yaml
from yaml.tokens import AliasToken
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import CIJobExistsRule, Profile
from repoproof.security import resolve_under_root

GITLAB_RESERVED = {
    "default", "include", "stages", "variables", "workflow", "image", "services",
    "before_script", "after_script", "cache", "pages",
}

class CICollector:
    name = "ci"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        specs = sorted({(rule.params.ci, rule.params.path) for rule in profile.rules
                        if isinstance(rule, CIJobExistsRule)})
        evidence: list[Evidence] = []
        for ci_type, subject in specs:
            path = resolve_under_root(context.root, subject)
            state = EvidenceState.UNAVAILABLE
            facts: dict[str, object] = {}
            if path.is_file() and path.stat().st_size <= context.max_read_bytes:
                try:
                    text = path.read_text(encoding="utf-8")
                    if sum(isinstance(token, AliasToken) for token in yaml.scan(text)) > 50:
                        raise yaml.YAMLError("alias limit exceeded")
                    document = yaml.safe_load(text)
                    mapping = document if isinstance(document, dict) else {}
                    jobs = sorted(str(key) for key, value in mapping.items()
                                  if isinstance(value, dict) and
                                  (ci_type != "gitlab" or str(key) not in GITLAB_RESERVED))
                    facts = {"jobs": tuple(jobs)}
                    state = EvidenceState.AVAILABLE
                except (UnicodeDecodeError, yaml.YAMLError):
                    state = EvidenceState.LIMITED
                    facts = {"reason": "unsafe_or_invalid_yaml"}
            evidence.append(Evidence(f"ci:{ci_type}:{subject}", "ci_config", subject,
                state, facts, collector_provenance(context, self.name, ci=ci_type)))
        return tuple(evidence)
```

```python
# src/repoproof/collectors/distribution.py
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile

PACKAGING = {
    "python": ("pyproject.toml", "repoproof.spec"),
    "docker": ("Dockerfile",),
    "npm": ("package.json",),
    "cargo": ("Cargo.toml",),
}

class DistributionCollector:
    name = "distribution"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        packaging = tuple(name for name, paths in PACKAGING.items()
                          if all((context.root / path).is_file() for path in paths))
        workflows = context.root / ".github" / "workflows"
        release_workflow = any(
            "release" in path.name.casefold() for pattern in ("*.yml", "*.yaml")
            for path in workflows.glob(pattern)
        ) if workflows.is_dir() else False
        return (Evidence("distribution:local", "distribution", ".", EvidenceState.AVAILABLE,
            {"packaging": packaging, "release_workflow": release_workflow},
            collector_provenance(context, self.name)),)
```

- [ ] **Step 5: Verify no input execution, then commit**

Run: `python -m pytest tests/integration/collectors/test_markdown.py tests/integration/collectors/test_ci.py tests/integration/collectors/test_distribution.py -q`

Run: `python -m pytest -q`

Expected: all tests pass; the unsafe YAML fixture produces `LIMITED` evidence and executes no command.

```bash
git add src/repoproof/collectors tests/integration/collectors
git commit -m "feat: collect markdown CI and distribution evidence"
```

---

### Task 5: Collect bounded local Git history without invoking a shell

**Files:**
- Create: `src/repoproof/collectors/git.py`
- Create: `tests/unit/collectors/test_git_runner.py`
- Create: `tests/integration/collectors/test_git.py`

**Interfaces:**
- Consumes: `AuditContext`, `Profile`, `Evidence`.
- Produces: injectable `GitRunner.run(root, args, timeout, max_output)` and evidence kind `git_history` with `is_repository`, `current_branch`, `default_branch`, `commit_count`, `branches`, and `merge_count`.

- [ ] **Step 1: Write failing runner and repository tests**

```python
# tests/unit/collectors/test_git_runner.py
from pathlib import Path
from unittest.mock import patch
from repoproof.collectors.git import GitRunner

def test_git_runner_uses_argument_array_and_never_shell(tmp_path: Path) -> None:
    with patch("repoproof.collectors.git.subprocess.run") as run:
        run.return_value.stdout = "main\n"
        run.return_value.returncode = 0
        result = GitRunner().run(tmp_path, ("branch", "--show-current"), 10.0, 1024)
    assert result == "main"
    _, kwargs = run.call_args
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == tmp_path
```

```python
# tests/integration/collectors/test_git.py
from pathlib import Path
import subprocess
from repoproof.collectors.base import AuditContext
from repoproof.collectors.git import GitCollector
from repoproof.profile.loader import load_profile

def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)

def test_git_history_counts_commits_and_merges(tmp_path: Path) -> None:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "a.txt").write_text("a")
    git(tmp_path, "add", "a.txt")
    git(tmp_path, "commit", "-m", "first")
    evidence = GitCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    assert evidence.facts["is_repository"] is True
    assert evidence.facts["commit_count"] == 1
    assert evidence.facts["current_branch"] == "main"
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/collectors/test_git_runner.py tests/integration/collectors/test_git.py -q`

Expected: collection fails because `collectors.git` does not exist.

- [ ] **Step 3: Implement the shell-free bounded adapter**

```python
# src/repoproof/collectors/git.py
from dataclasses import dataclass
from pathlib import Path
import subprocess
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile

@dataclass(frozen=True, slots=True)
class GitRunner:
    executable: str = "git"

    def run(self, root: Path, args: tuple[str, ...], timeout: float, max_output: int) -> str:
        completed = subprocess.run(
            [self.executable, *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("git command unavailable")
        return completed.stdout[:max_output].strip()

class GitCollector:
    name = "git"

    def __init__(self, runner: GitRunner | None = None) -> None:
        self.runner = runner or GitRunner()

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        run = lambda args: self.runner.run(context.root, args, context.timeout_seconds, 1024 * 1024)
        try:
            inside = run(("rev-parse", "--is-inside-work-tree")) == "true"
            current = run(("branch", "--show-current"))
            commits = int(run(("rev-list", "--count", "HEAD")))
            branches = tuple(sorted(filter(None, run(("for-each-ref", "--format=%(refname:short)", "refs/heads")).splitlines())))
            merges = int(run(("rev-list", "--count", "--merges", "HEAD")))
            facts = {
                "is_repository": inside,
                "current_branch": current,
                "default_branch": "main" if "main" in branches else "master" if "master" in branches else "",
                "commit_count": commits,
                "branches": branches,
                "merge_count": merges,
            }
            state = EvidenceState.AVAILABLE
        except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired, ValueError):
            facts = {"reason": "git_unavailable_or_not_repository"}
            state = EvidenceState.UNAVAILABLE
        return (Evidence("git:history", "git_history", ".", state, facts,
            collector_provenance(context, self.name)),)
```

- [ ] **Step 4: Verify unavailable-Git degradation and commit**

```python
# add to tests/integration/collectors/test_git.py
from repoproof.domain import EvidenceState
from repoproof.collectors.git import GitRunner

def test_missing_git_returns_unavailable_evidence(tmp_path: Path) -> None:
    collector = GitCollector(GitRunner(executable="missing-git-for-repoproof"))
    evidence = collector.collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    assert evidence.state is EvidenceState.UNAVAILABLE
    assert evidence.facts == {"reason": "git_unavailable_or_not_repository"}
```

Run: `python -m pytest tests/unit/collectors/test_git_runner.py tests/integration/collectors/test_git.py -q`

Run: `python -m pytest -q`

Expected: all tests pass on Windows and POSIX; Git is always called with `shell=False`.

```bash
git add src/repoproof/collectors/git.py tests/unit/collectors/test_git_runner.py tests/integration/collectors/test_git.py
git commit -m "feat: collect bounded local Git evidence"
```

---

### Task 6: Detect suspected secrets while making raw values unobservable

**Files:**
- Create: `src/repoproof/allowlist.py`
- Create: `src/repoproof/collectors/secrets.py`
- Create: `tests/unit/test_allowlist.py`
- Create: `tests/unit/collectors/test_secrets.py`
- Create: `tests/integration/collectors/test_secret_non_disclosure.py`

**Interfaces:**
- Consumes: `AuditContext`, `Profile`, `short_fingerprint`, file inventory evidence shape.
- Produces: evidence kind `secret_scan`; `facts["matches"]` is a tuple of `{category, path, line, fingerprint, allowlisted_for}` mappings and never contains raw match text.

- [ ] **Step 1: Write failing detection and non-disclosure tests**

```python
# tests/unit/collectors/test_secrets.py
from repoproof.collectors.secrets import shannon_entropy

def test_entropy_is_zero_for_repeated_value() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0

def test_entropy_is_high_for_mixed_value() -> None:
    assert shannon_entropy("Q9!sL2@pX7#vN4$k") > 3.5
```

```python
# tests/integration/collectors/test_secret_non_disclosure.py
import hashlib
from pathlib import Path
from repoproof.collectors.base import AuditContext
from repoproof.collectors.secrets import SecretCollector
from repoproof.profile.loader import load_profile

CANARY = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"

def test_token_match_contains_only_safe_metadata(tmp_path: Path) -> None:
    (tmp_path / "config.txt").write_text(f"token = '{CANARY}'\n", encoding="utf-8")
    evidence = SecretCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    match = evidence.facts["matches"][0]
    assert match["category"] == "token"
    assert match["path"] == "config.txt"
    assert match["line"] == 1
    assert len(match["fingerprint"]) == 8
    assert CANARY not in repr(evidence)

def test_private_key_and_sensitive_filename_are_detected(tmp_path: Path) -> None:
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nredacted-fixture-body\n", encoding="utf-8"
    )
    evidence = SecretCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    assert {item["category"] for item in evidence.facts["matches"]} == {
        "private_key", "sensitive_file"
    }
```

- [ ] **Step 2: Write a strict raw-secret-free allowlist test**

```python
# tests/unit/test_allowlist.py
from pathlib import Path
import pytest
from repoproof.allowlist import load_secret_allowlist
from repoproof.errors import UsageFailure

def test_allowlist_accepts_only_rule_path_and_short_fingerprint(tmp_path: Path) -> None:
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: tests/fixture.txt\n"
        "    fingerprint: 1a2b3c4d\n",
        encoding="utf-8",
    )
    assert load_secret_allowlist(tmp_path) == frozenset({
        ("security.secrets", "tests/fixture.txt", "1a2b3c4d")
    })

def test_allowlist_rejects_raw_value_field(tmp_path: Path) -> None:
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: x\n"
        "    fingerprint: 1a2b3c4d\n"
        "    value: never-allowed\n",
        encoding="utf-8",
    )
    with pytest.raises(UsageFailure, match="allowlist"):
        load_secret_allowlist(tmp_path)
```

- [ ] **Step 3: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/test_allowlist.py tests/unit/collectors/test_secrets.py tests/integration/collectors/test_secret_non_disclosure.py -q`

Expected: collection fails because `collectors.secrets` does not exist.

- [ ] **Step 4: Implement the strict allowlist and streaming classification**

```python
# src/repoproof/allowlist.py
from pathlib import Path
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from yaml.tokens import AliasToken
from repoproof.errors import UsageFailure
from repoproof.profile.models import SafeRepoPath

class AllowlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    path: SafeRepoPath
    fingerprint: str = Field(pattern=r"^[0-9a-f]{8}$")

class SecretAllowlist(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema: int = Field(ge=1, le=1)
    entries: tuple[AllowlistEntry, ...] = ()

def load_secret_allowlist(root: Path) -> frozenset[tuple[str, str, str]]:
    path = root / ".repoproofallowlist.yml"
    if not path.exists():
        return frozenset()
    if path.stat().st_size > 1024 * 1024:
        raise UsageFailure("Secret allowlist exceeds 1 MiB.", "Reduce the allowlist size.")
    try:
        text = path.read_text(encoding="utf-8")
        if sum(isinstance(token, AliasToken) for token in yaml.scan(text)) > 50:
            raise yaml.YAMLError("alias limit exceeded")
        document = yaml.safe_load(text)
        model = SecretAllowlist.model_validate(document)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise UsageFailure("Secret allowlist is invalid.",
                           "Use only schema, rule_id, path, and 8-hex fingerprint fields.") from exc
    return frozenset((entry.rule_id, entry.path, entry.fingerprint) for entry in model.entries)
```

```python
# src/repoproof/collectors/secrets.py
from collections import Counter
from fnmatch import fnmatch
import math
from pathlib import Path
import re
from repoproof.allowlist import load_secret_allowlist
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.models import Profile, SecretScanRule
from repoproof.security import short_fingerprint

TOKEN_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
ASSIGNMENT = re.compile(rb"(?i)(?:token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_+/=-]{20,255})")
SENSITIVE_NAMES = {"id_rsa", "id_ed25519", ".env", "credentials.json"}

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

class SecretCollector:
    name = "secrets"

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        rules = [rule for rule in profile.rules if isinstance(rule, SecretScanRule)]
        if not rules:
            return ()
        categories = {category for rule in rules for category in rule.params.categories}
        entropy_threshold = min(rule.params.entropy_threshold for rule in rules)
        allowlist = load_secret_allowlist(context.root)
        matches: list[dict[str, object]] = []
        for path in context.root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(context.root).as_posix()
            if all(any(fnmatch(relative, pattern) for pattern in rule.params.exclude_paths)
                   for rule in rules):
                continue
            if path.name.casefold() in SENSITIVE_NAMES and "sensitive_file" in categories:
                fingerprint = short_fingerprint(relative.encode())
                allowed = tuple(sorted(rule.id for rule in rules
                    if (rule.id, relative, fingerprint) in allowlist))
                matches.append({"category": "sensitive_file", "path": relative, "line": 1,
                                "fingerprint": fingerprint, "allowlisted_for": allowed})
            if path.stat().st_size > context.max_read_bytes:
                continue
            data = path.read_bytes()
            if b"\x00" in data[:8192]:
                continue
            for line_number, line in enumerate(data.splitlines(), start=1):
                candidates: list[tuple[str, bytes]] = []
                if "token" in categories:
                    candidates.extend(("token", found.group(0)) for pattern in TOKEN_PATTERNS
                                      for found in pattern.finditer(line))
                if "private_key" in categories:
                    candidates.extend(("private_key", found.group(0)) for found in PRIVATE_KEY.finditer(line))
                if "high_entropy" in categories:
                    candidates.extend(("high_entropy", found.group(1)) for found in ASSIGNMENT.finditer(line)
                                      if shannon_entropy(found.group(1).decode("ascii", "ignore"))
                                      >= entropy_threshold)
                seen: set[tuple[str, str]] = set()
                for category, raw in candidates:
                    key = (category, short_fingerprint(raw))
                    if key in seen:
                        continue
                    seen.add(key)
                    allowed = tuple(sorted(rule.id for rule in rules
                        if (rule.id, relative, key[1]) in allowlist))
                    matches.append({"category": category, "path": relative, "line": line_number,
                                    "fingerprint": key[1], "allowlisted_for": allowed})
        ordered = tuple(sorted(matches, key=lambda item:
            (str(item["path"]), int(item["line"]), str(item["category"]), str(item["fingerprint"]))))
        return (Evidence("secrets:scan", "secret_scan", ".", EvidenceState.AVAILABLE,
            {"matches": ordered}, collector_provenance(context, self.name)),)
```

- [ ] **Step 5: Verify exclusions and an actual allowlist suppression**

```python
# tests/integration/collectors/test_secret_non_disclosure.py (additional cases)
def test_excluded_path_never_reads_or_reports_canary(tmp_path: Path) -> None:
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text(CANARY, encoding="utf-8")
    evidence = SecretCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    assert evidence.facts["matches"] == ()
    assert CANARY not in repr(evidence)

def test_allowlist_marks_only_matching_rule_path_and_fingerprint(tmp_path: Path) -> None:
    target = tmp_path / "fixture.txt"
    target.write_text(CANARY, encoding="utf-8")
    fingerprint = hashlib.sha256(CANARY.encode()).hexdigest()[:8]
    (tmp_path / ".repoproofallowlist.yml").write_text(
        "schema: 1\nentries:\n"
        "  - rule_id: security.secrets\n"
        "    path: fixture.txt\n"
        f"    fingerprint: {fingerprint}\n",
        encoding="utf-8",
    )
    evidence = SecretCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))[0]
    token = next(item for item in evidence.facts["matches"] if item["category"] == "token")
    assert token["allowlisted_for"] == ("security.secrets",)
    assert CANARY not in repr(evidence)
```

- [ ] **Step 6: Verify GREEN and commit**

Run: `python -m pytest tests/unit/test_allowlist.py tests/unit/collectors/test_secrets.py tests/integration/collectors/test_secret_non_disclosure.py -q`

Run: `python -m pytest -q`

Expected: all tests pass and the canary is absent from every assertion-visible representation.

```bash
git add src/repoproof/allowlist.py src/repoproof/collectors/secrets.py tests/unit/test_allowlist.py tests/unit/collectors/test_secrets.py tests/integration/collectors/test_secret_non_disclosure.py
git commit -m "feat: add non-disclosing secret evidence"
```

---

### Task 7: Evaluate all six rule types with a pure deterministic engine

**Files:**
- Create: `src/repoproof/rules.py`
- Create: `tests/unit/rules/test_engine.py`
- Create: `tests/unit/rules/test_path_and_markdown.py`
- Create: `tests/unit/rules/test_ci_git_distribution_secret.py`
- Create: `tests/unit/rules/test_determinism.py`

**Interfaces:**
- Consumes: `Profile`, discriminated rules, `Sequence[Evidence]`.
- Produces: `required_collector_names(profile, offline)` and `evaluate(profile, evidence)`; no filesystem, subprocess, network, clock, Typer, Rich, or keyring dependency.

- [ ] **Step 1: Write failing status and collector-selection tests**

```python
# tests/unit/rules/test_engine.py
from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate, required_collector_names

def profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate({
        "schema": 1, "name": "test-policy", "description": "test", "rules": [rule]
    })

def test_missing_error_path_is_fail() -> None:
    policy = profile({"id": "docs.spec", "type": "path_exists", "severity": "error",
        "params": {"paths": ["SPEC.md"], "min_matches": 1}, "remediation": "Add it."})
    evidence = Evidence("files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE,
                        {"paths": ()}, {"collector": "files"})
    assert evaluate(policy, [evidence])[0].status is FindingStatus.FAIL

def test_missing_warning_path_is_warn() -> None:
    policy = profile({"id": "ci.github", "type": "path_exists", "severity": "warning",
        "params": {"paths": [".github/workflows/*.yml"], "min_matches": 1},
        "remediation": "Add it."})
    evidence = Evidence("files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE,
                        {"paths": ()}, {"collector": "files"})
    assert evaluate(policy, [evidence])[0].status is FindingStatus.WARN

def test_offline_never_selects_github_collector() -> None:
    policy = profile({"id": "git.process", "type": "git_history", "severity": "warning",
        "params": {"min_commits": 1, "accept_remote_pr": True},
        "remediation": "Add process evidence."})
    assert "github" not in required_collector_names(policy, offline=True)
```

- [ ] **Step 2: Write a complete rule-state matrix before implementation**

```python
# tests/unit/rules/test_path_and_markdown.py
from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate

def test_markdown_alias_and_completed_hash_pass() -> None:
    policy = Profile.model_validate({
        "schema": 1, "name": "test-policy", "description": "test",
        "rules": [{
            "id": "docs.readme", "type": "markdown_sections", "severity": "error",
            "params": {"path": "README.md", "headings": ["安装"],
                       "aliases": {"安装": ["Installation"]},
                       "completed_items_require_commit": True},
            "remediation": "Fix README.",
        }],
    })
    evidence = Evidence("markdown:README.md", "markdown", "README.md",
        EvidenceState.AVAILABLE,
        {"headings": ("installation",),
         "completed_items": ({"line": 4, "has_commit": True},)}, {})
    assert evaluate(policy, [evidence])[0].status is FindingStatus.PASS

def test_completed_item_without_hash_warns_at_exact_line() -> None:
    policy = Profile.model_validate({
        "schema": 1, "name": "test-policy", "description": "test",
        "rules": [{
            "id": "plan.evidence", "type": "markdown_sections", "severity": "warning",
            "params": {"path": "PLAN.md", "completed_items_require_commit": True},
            "remediation": "Add commit hash.",
        }],
    })
    evidence = Evidence("markdown:PLAN.md", "markdown", "PLAN.md", EvidenceState.AVAILABLE,
        {"headings": (), "completed_items": ({"line": 8, "has_commit": False},)}, {})
    finding = evaluate(policy, [evidence])[0]
    assert finding.status is FindingStatus.WARN
    assert finding.locations[0].line == 8
```

```python
# tests/unit/rules/test_ci_git_distribution_secret.py
import pytest
from repoproof.domain import Evidence, EvidenceState, FindingStatus
from repoproof.profile.models import Profile
from repoproof.rules import evaluate

def profile(rule: dict[str, object]) -> Profile:
    return Profile.model_validate({
        "schema": 1, "name": "test-policy", "description": "test", "rules": [rule]
    })

@pytest.mark.parametrize(
    ("rule", "evidence", "expected"),
    [
        (
            {"id": "ci.job", "type": "ci_job_exists", "severity": "error",
             "params": {"ci": "gitlab", "path": ".gitlab-ci.yml", "job": "unit-test"},
             "remediation": "Add job."},
            Evidence("ci:gitlab:.gitlab-ci.yml", "ci_config", ".gitlab-ci.yml",
                     EvidenceState.AVAILABLE, {"jobs": ("unit-test",)}, {}),
            FindingStatus.PASS,
        ),
        (
            {"id": "git.history", "type": "git_history", "severity": "error",
             "params": {"min_commits": 5}, "remediation": "Add commits."},
            Evidence("git:history", "git_history", ".", EvidenceState.UNAVAILABLE, {}, {}),
            FindingStatus.SKIP,
        ),
        (
            {"id": "dist.release", "type": "distribution_ready", "severity": "error",
             "params": {"allowed": ["python"], "required_paths": ["pyproject.toml"],
                        "require_release_workflow": True, "accept_published_release": True},
             "remediation": "Add release."},
            Evidence("distribution:local", "distribution", ".", EvidenceState.AVAILABLE,
                     {"packaging": ("python",), "release_workflow": True}, {}),
            FindingStatus.PASS,
        ),
        (
            {"id": "security.secrets", "type": "secret_scan", "severity": "error",
             "params": {"categories": ["token"], "entropy_threshold": 4.0,
                        "exclude_paths": []}, "remediation": "Remove it."},
            Evidence("secrets:scan", "secret_scan", ".", EvidenceState.AVAILABLE,
                     {"matches": ({"category": "token", "path": "x", "line": 1,
                                   "fingerprint": "12345678", "allowlisted_for": ()},)}, {}),
            FindingStatus.FAIL,
        ),
    ],
)
def test_rule_matrix(rule: dict[str, object], evidence: Evidence,
                     expected: FindingStatus) -> None:
    assert evaluate(profile(rule), [evidence])[0].status is expected
```

- [ ] **Step 3: Run rule tests and verify RED**

Run: `python -m pytest tests/unit/rules -q`

Expected: collection fails because `repoproof.rules` does not exist.

- [ ] **Step 4: Implement the pure registry, evidence lookup, and collector selection**

```python
# src/repoproof/rules.py
from collections.abc import Sequence
from fnmatch import fnmatch
from repoproof.domain import (
    Evidence, EvidenceState, Finding, FindingStatus, Location, status_for_failure,
)
from repoproof.profile.models import (
    CIJobExistsRule, DistributionReadyRule, GitHistoryRule, MarkdownSectionsRule,
    PathExistsRule, Profile, Rule, SecretScanRule,
)

def required_collector_names(profile: Profile, offline: bool) -> tuple[str, ...]:
    names = {"files"}
    type_to_collector = {
        "markdown_sections": "markdown",
        "ci_job_exists": "ci",
        "git_history": "git",
        "distribution_ready": "distribution",
        "secret_scan": "secrets",
    }
    names.update(type_to_collector[rule.type] for rule in profile.rules
                 if rule.type in type_to_collector)
    wants_remote = any(
        isinstance(rule, GitHistoryRule) and rule.params.accept_remote_pr or
        isinstance(rule, DistributionReadyRule) and rule.params.accept_published_release
        for rule in profile.rules
    )
    if wants_remote and not offline:
        names.add("github")
    return tuple(sorted(names))

def _find(evidence: Sequence[Evidence], kind: str, subject: str | None = None) -> Evidence | None:
    return next((item for item in evidence if item.kind == kind and
                 (subject is None or item.subject == subject)), None)

def _result(rule: Rule, passed: bool | None, message: str,
            evidence_ids: tuple[str, ...] = (), locations: tuple[Location, ...] = ()) -> Finding:
    status = FindingStatus.SKIP if passed is None else (
        FindingStatus.PASS if passed else status_for_failure(rule.severity)
    )
    return Finding(rule.id, status, rule.severity, message, locations,
                   evidence_ids, rule.remediation)
```

- [ ] **Step 5: Implement all six evaluators with explicit unavailable semantics**

```python
# continuation of src/repoproof/rules.py
def _path(rule: PathExistsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "file_inventory")
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "File inventory is unavailable.")
    paths = tuple(str(path) for path in item.facts["paths"])
    matched = tuple(sorted({path for pattern in rule.params.paths for path in paths
                            if fnmatch(path, pattern)}))
    return _result(rule, len(matched) >= rule.params.min_matches,
                   f"Matched {len(matched)} of {rule.params.min_matches} required paths.",
                   (item.id,), tuple(Location(path) for path in matched))

def _markdown(rule: MarkdownSectionsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "markdown", rule.params.path)
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, f"Markdown evidence unavailable for {rule.params.path}.")
    headings = {str(value).casefold() for value in item.facts["headings"]}
    required = []
    for heading in rule.params.headings:
        choices = (heading, *rule.params.aliases.get(heading, ()))
        required.append(any(" ".join(choice.casefold().split()) in headings for choice in choices))
    commit_checks = tuple(item.facts["completed_items"])
    commits_ok = (not rule.params.completed_items_require_commit or
                  all(bool(check["has_commit"]) for check in commit_checks))
    passed = all(required) and commits_ok
    bad_lines = tuple(Location(rule.params.path, int(check["line"])) for check in commit_checks
                      if not bool(check["has_commit"]))
    return _result(rule, passed, "Markdown headings and completed-item evidence checked.",
                   (item.id,), bad_lines)

def _ci(rule: CIJobExistsRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "ci_config", rule.params.path)
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, f"CI evidence unavailable for {rule.params.path}.")
    passed = rule.params.job in tuple(item.facts["jobs"])
    return _result(rule, passed, f"CI job {rule.params.job!r} checked.", (item.id,),
                   (Location(rule.params.path),))

def _git(rule: GitHistoryRule, evidence: Sequence[Evidence]) -> Finding:
    local = _find(evidence, "git_history")
    if local is None or local.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Local Git history is unavailable.")
    facts = local.facts
    commits_ok = int(facts["commit_count"]) >= rule.params.min_commits
    default = str(facts["default_branch"])
    branches_ok = not rule.params.require_non_default_branch or any(
        str(branch) != default for branch in tuple(facts["branches"])
    )
    process_needed = rule.params.require_non_default_branch
    local_process = bool(int(facts["merge_count"])) if rule.params.accept_local_merge else False
    remote = _find(evidence, "github_repository")
    remote_process = bool(remote and remote.state is EvidenceState.AVAILABLE and
                          int(remote.facts.get("merged_pull_requests", 0)) > 0)
    if process_needed and not (local_process or (rule.params.accept_remote_pr and remote_process)):
        if rule.params.accept_remote_pr and remote is None:
            return _result(rule, None, "Remote PR evidence is unavailable.", (local.id,))
        return _result(rule, False, "No accepted merge or pull request evidence.", (local.id,))
    return _result(rule, commits_ok and branches_ok, "Git history requirements checked.",
                   (local.id,) + ((remote.id,) if remote else ()))

def _distribution(rule: DistributionReadyRule, evidence: Sequence[Evidence]) -> Finding:
    local = _find(evidence, "distribution")
    if local is None or local.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Distribution evidence is unavailable.")
    packaging_ok = any(item in tuple(local.facts["packaging"]) for item in rule.params.allowed)
    inventory = _find(evidence, "file_inventory")
    paths = tuple(inventory.facts["paths"]) if inventory and inventory.state is EvidenceState.AVAILABLE else ()
    paths_ok = all(path in paths for path in rule.params.required_paths)
    release_ok = not rule.params.require_release_workflow or bool(local.facts["release_workflow"])
    remote = _find(evidence, "github_repository")
    if not release_ok and rule.params.accept_published_release and remote:
        release_ok = remote.state is EvidenceState.AVAILABLE and bool(remote.facts.get("has_release", False))
    if (not release_ok and rule.params.accept_published_release and
            (remote is None or remote.state is not EvidenceState.AVAILABLE)):
        return _result(rule, None, "Release evidence is unavailable.", (local.id,))
    return _result(rule, packaging_ok and paths_ok and release_ok,
                   "Packaging and Release readiness checked.", (local.id,))

def _secret(rule: SecretScanRule, evidence: Sequence[Evidence]) -> Finding:
    item = _find(evidence, "secret_scan")
    if item is None or item.state is not EvidenceState.AVAILABLE:
        return _result(rule, None, "Secret scan evidence is unavailable.")
    matches = tuple(match for match in item.facts["matches"]
        if str(match["category"]) in rule.params.categories
        and not any(fnmatch(str(match["path"]), pattern) for pattern in rule.params.exclude_paths)
        and rule.id not in tuple(match["allowlisted_for"]))
    locations = tuple(Location(str(match["path"]), int(match["line"])) for match in matches)
    safe_details = ", ".join(
        f"{match['category']} fingerprint={match['fingerprint']}" for match in matches
    )
    message = ("Secret scan found no suspected values." if not matches else
               f"Secret scan found {len(matches)} suspected values: <redacted>; {safe_details}.")
    return _result(rule, not matches, message,
                   (item.id,), locations)

def _evaluate_rule(rule: Rule, evidence: Sequence[Evidence]) -> Finding:
    if isinstance(rule, PathExistsRule):
        return _path(rule, evidence)
    if isinstance(rule, MarkdownSectionsRule):
        return _markdown(rule, evidence)
    if isinstance(rule, CIJobExistsRule):
        return _ci(rule, evidence)
    if isinstance(rule, GitHistoryRule):
        return _git(rule, evidence)
    if isinstance(rule, DistributionReadyRule):
        return _distribution(rule, evidence)
    if isinstance(rule, SecretScanRule):
        return _secret(rule, evidence)
    raise AssertionError(f"Unsupported validated rule: {type(rule).__name__}")

def evaluate(profile: Profile, evidence: Sequence[Evidence]) -> tuple[Finding, ...]:
    findings = (_evaluate_rule(rule, evidence) for rule in profile.rules)
    return tuple(sorted(findings, key=lambda item: item.rule_id))
```

- [ ] **Step 6: Prove determinism and all state transitions**

```python
# tests/unit/rules/test_determinism.py
from repoproof.domain import Evidence, EvidenceState
from repoproof.profile.loader import load_profile
from repoproof.rules import evaluate

def test_evaluation_is_repeatable_and_rule_sorted() -> None:
    evidence = (
        Evidence("files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE,
                 {"paths": ("SPEC.md",), "sizes": {}, "total_bytes": 0}, {}),
        Evidence("git:history", "git_history", ".", EvidenceState.UNAVAILABLE, {}, {}),
        Evidence("distribution:local", "distribution", ".", EvidenceState.AVAILABLE,
                 {"packaging": (), "release_workflow": False}, {}),
        Evidence("secrets:scan", "secret_scan", ".", EvidenceState.AVAILABLE,
                 {"matches": ()}, {}),
    )
    first = evaluate(load_profile("ai4se-b"), evidence)
    second = evaluate(load_profile("ai4se-b"), tuple(reversed(evidence)))
    assert first == second
    assert [finding.rule_id for finding in first] == sorted(f.rule_id for f in first)
```

Run: `python -m pytest tests/unit/rules -q`

Run: `python -m pytest -q`

Expected: all six rule types cover PASS plus their failure state and SKIP; both runs produce equal findings.

- [ ] **Step 7: Commit the rule engine**

```bash
git add src/repoproof/rules.py tests/unit/rules
git commit -m "feat: evaluate schema-one rules deterministically"
```

---

### Task 8: Build one schema-1 report and three semantically identical renderers

**Files:**
- Create: `src/repoproof/reporting/__init__.py`
- Create: `src/repoproof/reporting/model.py`
- Create: `src/repoproof/reporting/console.py`
- Create: `src/repoproof/reporting/json_reporter.py`
- Create: `src/repoproof/reporting/html_reporter.py`
- Create: `src/repoproof/reporting/output.py`
- Create: `tests/unit/reporting/test_model.py`
- Create: `tests/unit/reporting/test_console.py`
- Create: `tests/unit/reporting/test_json_html.py`
- Create: `tests/integration/reporting/test_atomic_output.py`

**Interfaces:**
- Consumes: `Profile`, `Finding`, `AuditReport`, `profile_hash`.
- Produces: `build_report(...)`, `report_to_dict(report)`, `render_console`, `render_json`, `render_html`, `atomic_write_text`.

- [ ] **Step 1: Write failing schema, parity, escaping, and atomic-write tests**

```python
# tests/unit/reporting/test_json_html.py
import json
from datetime import datetime, timezone
from pathlib import Path
from repoproof.domain import Finding, FindingStatus, Location, Severity
from repoproof.profile.loader import load_profile
from repoproof.reporting.html_reporter import render_html
from repoproof.reporting.json_reporter import render_json
from repoproof.reporting.model import build_report

def sample_report():
    finding = Finding("docs.spec", FindingStatus.FAIL, Severity.ERROR,
        "<script>alert(1)</script>", (Location("a&b.md", 3),), ("files.inventory",), "Add it.")
    return build_report(load_profile("ai4se-b"), Path("repo"),
        [finding], [], {"total": 1}, datetime(2026, 7, 29, tzinfo=timezone.utc))

def test_json_and_html_share_finding_ids_and_states() -> None:
    report = sample_report()
    payload = json.loads(render_json(report))
    html = render_html(report)
    assert payload["report_schema"] == 1
    assert payload["findings"][0]["rule_id"] == "docs.spec"
    assert 'data-rule-id="docs.spec"' in html
    assert 'data-status="FAIL"' in html

def test_html_is_escaped_and_self_contained() -> None:
    html = render_html(sample_report())
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "a&amp;b.md" in html
    assert "<script" not in html.casefold()
    assert "http://" not in html and "https://" not in html
```

```python
# tests/unit/reporting/test_model.py
from datetime import datetime, timezone
from pathlib import Path
from repoproof.domain import Finding, FindingStatus, Severity, ExitCode
from repoproof.profile.loader import load_profile
from repoproof.reporting.model import build_report, report_to_dict

def test_report_sorts_status_then_rule_and_counts_exit() -> None:
    findings = [
        Finding("z.pass", FindingStatus.PASS, Severity.ERROR, "ok", (), (), "none"),
        Finding("a.fail", FindingStatus.FAIL, Severity.ERROR, "bad", (), (), "fix"),
    ]
    report = build_report(load_profile("ai4se-b"), Path("repo"), findings, [], {},
                          datetime(2026, 7, 29, tzinfo=timezone.utc))
    assert [item.rule_id for item in report.findings] == ["a.fail", "z.pass"]
    assert report.exit_code is ExitCode.FINDINGS
    assert report_to_dict(report)["summary"]["FAIL"] == 1
```

```python
# tests/unit/reporting/test_console.py
from datetime import datetime, timezone
from pathlib import Path
from repoproof.domain import Finding, FindingStatus, Location, Severity
from repoproof.profile.loader import load_profile
from repoproof.reporting.console import render_console
from repoproof.reporting.model import build_report

def test_plain_console_has_no_ansi_and_hides_pass() -> None:
    finding = Finding("docs.spec", FindingStatus.FAIL, Severity.ERROR, "missing",
                      (Location("SPEC.md"),), (), "Add it.")
    report = build_report(load_profile("ai4se-b"), Path("repo"), [finding], [], {},
                          datetime(2026, 7, 29, tzinfo=timezone.utc))
    text = render_console(report, color=False, verbose=False)
    assert "\x1b[" not in text
    assert "[FAIL] docs.spec" in text
```

```python
# tests/integration/reporting/test_atomic_output.py
from pathlib import Path
from unittest.mock import patch
import pytest
from repoproof.reporting.output import atomic_write_text

def test_failed_replace_leaves_existing_report_intact(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("old", encoding="utf-8")
    with patch("repoproof.reporting.output.os.replace", side_effect=OSError("blocked")):
        with pytest.raises(OSError, match="blocked"):
            atomic_write_text(report, "new")
    assert report.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []
```

- [ ] **Step 2: Run reporting tests and verify RED**

Run: `python -m pytest tests/unit/reporting tests/integration/reporting -q`

Expected: collection fails because the reporting package does not exist.

- [ ] **Step 3: Implement stable schema conversion and exit calculation**

```python
# src/repoproof/reporting/model.py
from datetime import datetime
from pathlib import Path
from collections.abc import Mapping, Sequence
from repoproof import __version__
from repoproof.domain import AuditReport, ExitCode, Finding, FindingStatus
from repoproof.profile.loader import profile_hash
from repoproof.profile.models import Profile

STATUS_ORDER = {"FAIL": 0, "WARN": 1, "SKIP": 2, "PASS": 3}

def build_report(profile: Profile, root: Path, findings: Sequence[Finding],
                 diagnostics: Sequence[str], timings_ms: Mapping[str, int],
                 generated_at: datetime) -> AuditReport:
    ordered = tuple(sorted(findings, key=lambda finding: (
        STATUS_ORDER[finding.status.value], finding.rule_id,
        tuple((location.path, location.line or 0) for location in finding.locations),
    )))
    exit_code = ExitCode.FINDINGS if any(
        finding.status is FindingStatus.FAIL for finding in ordered
    ) else ExitCode.OK
    return AuditReport(1, __version__, generated_at, root.name, profile.name, profile.schema,
        profile_hash(profile), ordered, tuple(profile.manual_checks), tuple(diagnostics),
        dict(sorted(timings_ms.items())), exit_code)

def report_to_dict(report: AuditReport) -> dict[str, object]:
    counts = {status.value: sum(f.status is status for f in report.findings)
              for status in FindingStatus}
    return {
        "report_schema": report.report_schema,
        "tool_version": report.tool_version,
        "generated_at": report.generated_at.isoformat().replace("+00:00", "Z"),
        "repository": {"name": report.repository_name},
        "profile": {"name": report.profile_name, "schema": report.profile_schema,
                    "sha256": report.profile_hash},
        "summary": {**counts, "exit_code": int(report.exit_code)},
        "findings": [{
            "rule_id": item.rule_id, "status": item.status.value,
            "severity": item.severity.value, "message": item.message,
            "locations": [{"path": loc.path, **({"line": loc.line} if loc.line else {})}
                          for loc in item.locations],
            "evidence_ids": list(item.evidence_ids), "remediation": item.remediation,
        } for item in report.findings],
        "manual_checks": list(report.manual_checks),
        "diagnostics": list(report.diagnostics),
        "timings_ms": dict(report.timings_ms),
    }
```

- [ ] **Step 4: Implement console, canonical JSON, escaped HTML, and atomic output**

```python
# src/repoproof/reporting/json_reporter.py
import json
from repoproof.domain import AuditReport
from repoproof.reporting.model import report_to_dict

def render_json(report: AuditReport) -> str:
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
```

```python
# src/repoproof/reporting/html_reporter.py
from html import escape
from repoproof.domain import AuditReport

def render_html(report: AuditReport) -> str:
    rows = "".join(
        f'<article data-rule-id="{escape(item.rule_id)}" data-status="{item.status.value}">'
        f"<h2>{escape(item.rule_id)} — {item.status.value}</h2>"
        f"<p>{escape(item.message)}</p><p>Fix: {escape(item.remediation)}</p>"
        + "".join(f"<code>{escape(loc.path)}{':' + str(loc.line) if loc.line else ''}</code>"
                  for loc in item.locations) + "</article>"
        for item in report.findings
    )
    manual = "".join(f"<li>{escape(item)}</li>" for item in report.manual_checks)
    return (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>RepoProof report</title><style>"
        "body{font:16px system-ui;max-width:960px;margin:auto;padding:2rem}"
        "article{border:1px solid #bbb;border-radius:.5rem;padding:1rem;margin:1rem 0}"
        "code{display:block;margin:.25rem 0}</style><body>"
        f"<h1>RepoProof report</h1><p>Schema {report.report_schema}; "
        f"tool {escape(report.tool_version)}; generated {escape(report.generated_at.isoformat())}</p>"
        f"{rows}<section><h2>Manual review</h2><ul>{manual}</ul></section></body></html>\n"
    )
```

```python
# src/repoproof/reporting/console.py
from io import StringIO
from rich.console import Console
from repoproof.domain import AuditReport, FindingStatus

def render_console(report: AuditReport, *, color: bool, verbose: bool) -> str:
    output = StringIO()
    console = Console(file=output, force_terminal=color, color_system="standard" if color else None)
    visible = report.findings if verbose else tuple(
        item for item in report.findings if item.status is not FindingStatus.PASS
    )
    for item in visible:
        console.print(f"[{item.status.value}] {item.rule_id}: {item.message}", markup=False)
        console.print(f"  fix: {item.remediation}", markup=False)
    if report.manual_checks:
        console.print("Manual review:", markup=False)
        for check in report.manual_checks:
            console.print(f"  - {check}", markup=False)
    console.print(f"exit: {int(report.exit_code)}", markup=False)
    return output.getvalue()
```

```python
# src/repoproof/reporting/output.py
import os
from pathlib import Path
import tempfile

def atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp",
                                            dir=target.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
```

- [ ] **Step 5: Verify reporter parity and non-disclosure**

Run: `python -m pytest tests/unit/reporting tests/integration/reporting -q`

Run: `python -m pytest -q`

Expected: all tests pass; HTML contains no script or external URL; JSON and HTML expose identical rule IDs/statuses.

- [ ] **Step 6: Commit report generation**

```bash
git add src/repoproof/reporting tests/unit/reporting tests/integration/reporting
git commit -m "feat: render deterministic console JSON and HTML reports"
```

---

### Task 9: Orchestrate offline audits and expose the complete audit CLI

**Files:**
- Create: `src/repoproof/app.py`
- Modify: `src/repoproof/cli.py`
- Create: `tests/unit/test_app.py`
- Create: `tests/integration/test_cli_audit.py`
- Create: `tests/integration/test_cli_output_routing.py`

**Interfaces:**
- Consumes: all local collectors, `required_collector_names`, `evaluate`, `build_report`, three renderers.
- Produces: `AuditRequest`, `AppDependencies`, `run_audit`; CLI signature from SPEC; stable 0/1/2/3 boundary.

- [ ] **Step 1: Write failing orchestration and CLI-exit tests**

```python
# tests/unit/test_app.py
from datetime import datetime, timezone
from pathlib import Path
from repoproof.app import AppDependencies, AuditRequest, run_audit
from repoproof.domain import Evidence, EvidenceState, ExitCode

class FakeCollector:
    def __init__(self, evidence: tuple[Evidence, ...]) -> None:
        self.evidence = evidence
    def collect(self, context, profile):
        return self.evidence

def test_offline_app_runs_only_required_local_collectors(tmp_path: Path) -> None:
    (tmp_path / "SPEC.md").write_text("spec")
    evidence = Evidence("files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE,
                        {"paths": ("SPEC.md",), "sizes": {}, "total_bytes": 4}, {})
    dependencies = AppDependencies(
        collectors={"files": FakeCollector((evidence,))},
        clock=lambda: datetime(2026, 7, 29, tzinfo=timezone.utc),
        monotonic_ns=iter((0, 1_000_000, 2_000_000, 3_000_000)).__next__,
    )
    report = run_audit(AuditRequest(tmp_path, "ai4se-b", True), dependencies)
    assert report.exit_code in (ExitCode.OK, ExitCode.FINDINGS)
    assert report.repository_name == tmp_path.name
```

```python
# tests/integration/test_cli_audit.py
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

def test_nonexistent_repository_exits_three(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["audit", str(tmp_path / "missing")])
    assert result.exit_code == 3
    assert "repository" in result.stderr.casefold()

def test_invalid_profile_exits_two(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["audit", str(tmp_path), "--profile", "missing.yml"])
    assert result.exit_code == 2
    assert "profile" in result.stderr.casefold()
```

```python
# tests/integration/test_cli_output_routing.py
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

def test_multiple_file_formats_require_directory_and_write_after_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("# repo\n", encoding="utf-8")
    output = tmp_path / "reports"
    output.mkdir()
    before = {path.relative_to(repository): path.read_bytes()
              for path in repository.rglob("*") if path.is_file()}
    result = CliRunner().invoke(app, ["audit", str(repository), "--offline",
        "--format", "json", "--format", "html", "--output", str(output)])
    after = {path.relative_to(repository): path.read_bytes()
             for path in repository.rglob("*") if path.is_file()}
    assert result.exit_code == 1
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    assert after == before
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/test_app.py tests/integration/test_cli_audit.py tests/integration/test_cli_output_routing.py -q`

Expected: tests fail because `AuditRequest`, `AppDependencies`, and the audit command do not exist.

- [ ] **Step 3: Implement injected audit orchestration**

```python
# src/repoproof/app.py
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic_ns
from repoproof.collectors.base import AuditContext, Collector
from repoproof.collectors.ci import CICollector
from repoproof.collectors.distribution import DistributionCollector
from repoproof.collectors.files import FileCollector
from repoproof.collectors.git import GitCollector
from repoproof.collectors.markdown import MarkdownCollector
from repoproof.collectors.secrets import SecretCollector
from repoproof.domain import AuditReport, Evidence
from repoproof.errors import RuntimeFailure
from repoproof.profile.loader import load_profile
from repoproof.reporting.model import build_report
from repoproof.rules import evaluate, required_collector_names

@dataclass(frozen=True, slots=True)
class AuditRequest:
    repository: Path
    profile: str = "ai4se-b"
    offline: bool = False

@dataclass(frozen=True, slots=True)
class AppDependencies:
    collectors: Mapping[str, Collector]
    clock: Callable[[], datetime]
    monotonic_ns: Callable[[], int]

def default_dependencies() -> AppDependencies:
    return AppDependencies({
        "files": FileCollector(), "markdown": MarkdownCollector(), "ci": CICollector(),
        "distribution": DistributionCollector(), "git": GitCollector(), "secrets": SecretCollector(),
    }, lambda: datetime.now(timezone.utc), monotonic_ns)

def run_audit(request: AuditRequest, dependencies: AppDependencies) -> AuditReport:
    root = request.repository.resolve(strict=False)
    if not root.is_dir():
        raise RuntimeFailure("Repository is not a readable directory.", "Check the repository path.")
    profile = load_profile(request.profile)
    snapshot_at = dependencies.clock()
    context = AuditContext(root, request.offline, snapshot_at=snapshot_at)
    evidence: list[Evidence] = []
    timings: dict[str, int] = {}
    for name in required_collector_names(profile, request.offline):
        collector = dependencies.collectors.get(name)
        if collector is None:
            continue
        started = dependencies.monotonic_ns()
        evidence.extend(collector.collect(context, profile))
        timings[name] = (dependencies.monotonic_ns() - started) // 1_000_000
    findings = evaluate(profile, evidence)
    return build_report(profile, root, findings, (), timings, snapshot_at)
```

- [ ] **Step 4: Implement CLI parsing, output routing, and sanitized exception mapping**

```python
# audit command addition to src/repoproof/cli.py
from enum import Enum
import sys
from typing import Annotated
from repoproof.app import AuditRequest, default_dependencies, run_audit
from repoproof.errors import RuntimeFailure
from repoproof.reporting.console import render_console
from repoproof.reporting.html_reporter import render_html
from repoproof.reporting.json_reporter import render_json
from repoproof.reporting.output import atomic_write_text

class ReportFormat(str, Enum):
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"

@app.command()
def audit(
    repository: Path = Path("."),
    profile: str = typer.Option("ai4se-b", "--profile"),
    formats: Annotated[list[ReportFormat] | None, typer.Option("--format")] = None,
    output: Path | None = typer.Option(None, "--output"),
    offline: bool = typer.Option(False, "--offline"),
    no_color: bool = typer.Option(False, "--no-color"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    selected = formats or [ReportFormat.CONSOLE]
    try:
        report = run_audit(AuditRequest(repository, profile, offline), default_dependencies())
        non_console = [item for item in selected if item is not ReportFormat.CONSOLE]
        if len(non_console) > 1 and (output is None or not output.is_dir()):
            raise UsageFailure("Multiple file formats require an output directory.",
                               "Pass --output with an existing directory.")
        for item in selected:
            if item is ReportFormat.CONSOLE:
                typer.echo(render_console(
                    report, color=not no_color and sys.stdout.isatty(), verbose=verbose
                ), nl=False)
            elif item is ReportFormat.JSON:
                target = output / "report.json" if output and output.is_dir() else output
                if target is None:
                    typer.echo(render_json(report), nl=False)
                else:
                    atomic_write_text(target, render_json(report))
            else:
                target = output / "report.html" if output and output.is_dir() else output
                if target is None:
                    typer.echo(render_html(report), nl=False)
                else:
                    atomic_write_text(target, render_html(report))
        raise typer.Exit(int(report.exit_code))
    except UsageFailure as exc:
        typer.echo(f"usage: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    except RuntimeFailure as exc:
        typer.echo(f"runtime: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(3) from None
    except typer.Exit:
        raise
    except Exception:
        typer.echo("runtime: audit failed safely\nfix: rerun with --verbose or report the failure", err=True)
        raise typer.Exit(3) from None
```

- [ ] **Step 5: Verify output path semantics, read-only behavior, and exit codes**

Run: `python -m pytest tests/unit/test_app.py tests/integration/test_cli_audit.py tests/integration/test_cli_output_routing.py -q`

Run: `python -m pytest -q`

Expected: PASS fixture exits 0, FAIL fixture exits 1, invalid profile exits 2, unreadable/missing repository exits 3; repository contents are byte-identical except an explicitly requested report path written after scanning.

- [ ] **Step 6: Commit the offline CLI**

```bash
git add src/repoproof/app.py src/repoproof/cli.py tests/unit/test_app.py tests/integration/test_cli_audit.py tests/integration/test_cli_output_routing.py
git commit -m "feat: expose offline repository audit CLI"
```

---

### Task 10: Implement keyring-only credential lifecycle and auth commands

**Files:**
- Create: `src/repoproof/credentials.py`
- Modify: `src/repoproof/cli.py`
- Create: `tests/unit/test_credentials.py`
- Create: `tests/integration/test_cli_auth.py`

**Interfaces:**
- Consumes: injected keyring backend; `UsageFailure`.
- Produces: `CredentialStore.login(host, token)`, `get(host)`, `configured(host)`, `logout(host)`, `backend_name()`; `auth login/status/logout`.

- [ ] **Step 1: Write failing fake-keyring lifecycle and CLI disclosure tests**

```python
# tests/unit/test_credentials.py
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

def test_login_update_status_logout_lifecycle() -> None:
    backend = FakeKeyring()
    store = CredentialStore(backend)
    store.login("github.com", "first-secret")
    assert store.configured("github.com") is True
    store.login("github.com", "second-secret")
    assert store.get("github.com") == "second-secret"
    store.logout("github.com")
    store.logout("github.com")
    assert store.configured("github.com") is False

def test_host_rejects_scheme_path_and_port() -> None:
    for value in ("https://github.com", "github.com/path", "github.com:443"):
        with pytest.raises(UsageFailure, match="host"):
            normalize_host(value)
```

```python
# tests/integration/test_cli_auth.py
from typer.testing import CliRunner
from repoproof.cli import app

TOKEN = "github_pat_" + "canary_0123456789abcdef"

class FakeStore:
    def __init__(self) -> None:
        self.token: str | None = None
    def login(self, host: str, token: str) -> None:
        self.token = token
    def configured(self, host: str) -> bool:
        return self.token is not None
    def backend_name(self) -> str:
        return "FakeKeyring"

def test_auth_status_never_prints_token(monkeypatch) -> None:
    store = FakeStore()
    monkeypatch.setattr("repoproof.cli._credential_store", lambda: store)
    monkeypatch.setattr("repoproof.cli._read_hidden_token", lambda: TOKEN)
    login = CliRunner().invoke(app, ["auth", "login"])
    status = CliRunner().invoke(app, ["auth", "status"])
    combined = login.stdout + login.stderr + status.stdout + status.stderr
    assert TOKEN not in combined
    assert "configured: yes" in status.stdout
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/test_credentials.py tests/integration/test_cli_auth.py -q`

Expected: collection fails because credential storage and auth commands do not exist.

- [ ] **Step 3: Implement keyring-only storage with no secret-bearing representation**

```python
# src/repoproof/credentials.py
from dataclasses import dataclass
from typing import Protocol
from repoproof.errors import UsageFailure

SERVICE = "repoproof.github"

def normalize_host(host: str) -> str:
    normalized = host.strip().casefold().rstrip(".")
    if (not normalized or "/" in normalized or ":" in normalized or
            not all(part and all(char.isalnum() or char == "-" for char in part)
                    for part in normalized.split("."))):
        raise UsageFailure("GitHub host is invalid.",
                           "Pass a hostname such as github.com without scheme, port, or path.")
    return normalized

class KeyringBackend(Protocol):
    def set_password(self, service: str, account: str, value: str) -> None: ...
    def get_password(self, service: str, account: str) -> str | None: ...
    def delete_password(self, service: str, account: str) -> None: ...

@dataclass(slots=True, repr=False)
class CredentialStore:
    backend: KeyringBackend

    def login(self, host: str, token: str) -> None:
        host = normalize_host(host)
        if not token.strip():
            raise UsageFailure("Token cannot be empty.", "Enter a non-empty Token interactively.")
        try:
            self.backend.set_password(SERVICE, host, token)
        except Exception as exc:
            raise UsageFailure("System keyring is unavailable.",
                               "Enable an OS keyring backend; plaintext fallback is disabled.") from exc

    def get(self, host: str) -> str | None:
        host = normalize_host(host)
        try:
            return self.backend.get_password(SERVICE, host)
        except Exception as exc:
            raise UsageFailure("System keyring is unavailable.", "Enable an OS keyring backend.") from exc

    def configured(self, host: str) -> bool:
        return self.get(host) is not None

    def logout(self, host: str) -> None:
        host = normalize_host(host)
        if not self.configured(host):
            return
        try:
            self.backend.delete_password(SERVICE, host)
        except Exception as exc:
            raise UsageFailure("Credential could not be deleted.", "Check the OS keyring backend.") from exc

    def backend_name(self) -> str:
        return type(self.backend).__name__
```

- [ ] **Step 4: Implement hidden interactive auth commands**

```python
# auth additions to src/repoproof/cli.py
import getpass
import keyring
from repoproof.credentials import CredentialStore

auth_app = typer.Typer(help="Manage optional GitHub credentials in the OS keyring.")
app.add_typer(auth_app, name="auth")

def _credential_store() -> CredentialStore:
    return CredentialStore(keyring.get_keyring())

def _read_hidden_token() -> str:
    if not sys.stdin.isatty():
        raise UsageFailure("auth login requires interactive input.",
                           "Run auth login in an interactive terminal.")
    return getpass.getpass("GitHub Token: ")

@auth_app.command("login")
def auth_login(host: str = typer.Option("github.com", "--host")) -> None:
    try:
        _credential_store().login(host, _read_hidden_token())
    except UsageFailure as exc:
        typer.echo(f"usage: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"credential stored for {host}")

@auth_app.command("status")
def auth_status(host: str = typer.Option("github.com", "--host")) -> None:
    try:
        store = _credential_store()
        configured = "yes" if store.configured(host) else "no"
        typer.echo(f"host: {host}\nconfigured: {configured}\nbackend: {store.backend_name()}")
    except UsageFailure as exc:
        typer.echo(f"usage: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None

@auth_app.command("logout")
def auth_logout(host: str = typer.Option("github.com", "--host")) -> None:
    try:
        _credential_store().logout(host)
    except UsageFailure as exc:
        typer.echo(f"usage: {exc.message}\nfix: {exc.remediation}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"credential cleared for {host}")
```

- [ ] **Step 5: Verify unavailable-keyring and non-interactive failure behavior**

Run: `python -m pytest tests/unit/test_credentials.py tests/integration/test_cli_auth.py -q`

Run: `python -m pytest -q`

Expected: all tests pass; empty input, non-interactive stdin, and unavailable keyring exit 2 without writing a file or printing the Token.

- [ ] **Step 6: Commit credential lifecycle**

```bash
git add src/repoproof/credentials.py src/repoproof/cli.py tests/unit/test_credentials.py tests/integration/test_cli_auth.py
git commit -m "feat: manage GitHub credentials through keyring"
```

---

### Task 11: Add optional HTTPS-only GitHub evidence with partial-failure preservation

**Files:**
- Create: `src/repoproof/github.py`
- Create: `src/repoproof/collectors/github.py`
- Modify: `src/repoproof/collectors/git.py`
- Modify: `src/repoproof/app.py`
- Modify: `src/repoproof/reporting/model.py`
- Create: `tests/unit/test_github.py`
- Create: `tests/unit/collectors/test_github.py`
- Create: `tests/integration/test_remote_degradation.py`

**Interfaces:**
- Consumes: `CredentialStore`, injected `httpx.Client`, local Git evidence `repository_slug`, `AuditContext.offline`.
- Produces: evidence kind `github_repository` with `default_branch`, `merged_pull_requests`, `has_release`, and `latest_actions_status`; network/auth errors set `facts["runtime_error"] = True`, while missing Token sets it to `False`.

- [ ] **Step 1: Write failing HTTPS, Token, and redaction tests**

```python
# tests/unit/test_github.py
import httpx
import pytest
from repoproof.github import GitHubGateway

class FakeCredentials:
    def __init__(self, token: str | None) -> None:
        self.token = token
    def get(self, host: str) -> str | None:
        return self.token

def test_gateway_rejects_non_https_base_url() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        GitHubGateway(FakeCredentials("secret"), httpx.Client(), "http://github.com")

def test_gateway_sends_token_only_in_authorization_header() -> None:
    seen: list[httpx.Request] = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"default_branch": "main"}, request=request)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    gateway = GitHubGateway(FakeCredentials("canary-token"), client)
    assert gateway.repository("owner", "repo")["default_branch"] == "main"
    assert seen[0].headers["Authorization"] == "Bearer canary-token"
    assert "canary-token" not in str(seen[0].url)
    assert "canary-token" not in repr(gateway)
    gateway.close()
```

```python
# tests/unit/collectors/test_github.py
from pathlib import Path
from repoproof.collectors.base import AuditContext
from repoproof.collectors.github import GitHubCollector
from repoproof.domain import EvidenceState
from repoproof.profile.loader import load_profile

class FakeGateway:
    def repository(self, owner: str, repo: str) -> dict[str, object]:
        return {"default_branch": "main"}
    def merged_pull_request_count(self, owner: str, repo: str) -> int:
        return 2
    def has_release(self, owner: str, repo: str) -> bool:
        return True
    def latest_actions_status(self, owner: str, repo: str) -> str:
        return "success"
    def close(self) -> None:
        pass

def test_collector_returns_only_structured_remote_facts(tmp_path: Path) -> None:
    evidence = GitHubCollector(FakeGateway(), "owner/repo").collect(
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
```

- [ ] **Step 2: Write missing-Token and network-failure preservation tests**

```python
# tests/integration/test_remote_degradation.py
from datetime import datetime, timezone
from pathlib import Path
from repoproof.app import AppDependencies, AuditRequest, run_audit
from repoproof.domain import Evidence, EvidenceState, ExitCode

class StaticCollector:
    def __init__(self, *evidence: Evidence) -> None:
        self.evidence = evidence
    def collect(self, context, profile):
        return self.evidence

def dependencies(remote: Evidence) -> AppDependencies:
    files = Evidence("files.inventory", "file_inventory", ".", EvidenceState.AVAILABLE,
                     {"paths": (), "sizes": {}, "total_bytes": 0}, {})
    return AppDependencies(
        collectors={"files": StaticCollector(files)},
        clock=lambda: datetime(2026, 7, 29, tzinfo=timezone.utc),
        monotonic_ns=iter(range(20)).__next__,
        github_collector_factory=lambda slug: StaticCollector(remote),
    )

def test_missing_token_skips_remote_rules_without_runtime_exit(tmp_path: Path) -> None:
    remote = Evidence("github:repository", "github_repository", ".",
        EvidenceState.UNAVAILABLE, {"reason": "token_missing", "runtime_error": False}, {})
    report = run_audit(AuditRequest(tmp_path, "ai4se-b", False), dependencies(remote))
    assert report.exit_code in (ExitCode.OK, ExitCode.FINDINGS)

def test_network_failure_preserves_local_findings_and_exits_three(tmp_path: Path) -> None:
    remote = Evidence("github:repository", "github_repository", ".",
        EvidenceState.UNAVAILABLE, {"reason": "network_error", "runtime_error": True}, {})
    report = run_audit(AuditRequest(tmp_path, "ai4se-b", False), dependencies(remote))
    assert report.exit_code is ExitCode.RUNTIME
    assert any(finding.rule_id == "docs.required" for finding in report.findings)
```

- [ ] **Step 3: Run focused tests and verify RED**

Run: `python -m pytest tests/unit/test_github.py tests/unit/collectors/test_github.py tests/integration/test_remote_degradation.py -q`

Expected: collection fails because the gateway and GitHub collector do not exist.

- [ ] **Step 4: Implement the HTTPS-only gateway**

```python
# src/repoproof/github.py
from dataclasses import dataclass
from urllib.parse import urlparse
import httpx
from repoproof.credentials import CredentialStore

@dataclass(slots=True, repr=False)
class GitHubGateway:
    credentials: CredentialStore
    client: httpx.Client
    base_url: str = "https://github.com"
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("GitHub base URL must use HTTPS")

    @property
    def host(self) -> str:
        hostname = urlparse(self.base_url).hostname
        assert hostname is not None
        return hostname

    def _get(self, path: str, params: dict[str, str] | None = None) -> object:
        token = self.credentials.get(self.host)
        if token is None:
            raise LookupError("token_missing")
        response = self.client.get(
            f"https://api.{self.host}{path}" if self.host == "github.com"
            else f"{self.base_url}/api/v3{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def repository(self, owner: str, repo: str) -> dict[str, object]:
        result = self._get(f"/repos/{owner}/{repo}")
        return dict(result) if isinstance(result, dict) else {}

    def merged_pull_request_count(self, owner: str, repo: str) -> int:
        result = self._get(f"/repos/{owner}/{repo}/pulls", {"state": "closed", "per_page": "100"})
        return sum(bool(item.get("merged_at")) for item in result if isinstance(item, dict)) \
            if isinstance(result, list) else 0

    def has_release(self, owner: str, repo: str) -> bool:
        result = self._get(f"/repos/{owner}/{repo}/releases", {"per_page": "1"})
        return bool(result) if isinstance(result, list) else False

    def latest_actions_status(self, owner: str, repo: str) -> str | None:
        result = self._get(f"/repos/{owner}/{repo}/actions/runs", {"per_page": "1"})
        runs = result.get("workflow_runs", []) if isinstance(result, dict) else []
        return str(runs[0].get("conclusion") or runs[0].get("status")) if runs else None

    def close(self) -> None:
        self.client.close()
```

- [ ] **Step 5: Parse a safe repository slug and collect remote metadata**

```python
# helper added to src/repoproof/collectors/git.py
import re

ORIGIN_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
)

def repository_slug(origin_url: str) -> str | None:
    match = ORIGIN_RE.fullmatch(origin_url.strip())
    return f"{match.group(1)}/{match.group(2)}" if match else None
```

Replace the Git facts construction in `GitCollector.collect` with this exact safe origin lookup;
a missing origin must not make otherwise valid local history unavailable:

```python
try:
    origin_url = run(("remote", "get-url", "origin"))
    slug = repository_slug(origin_url)
except RuntimeError:
    slug = None
finally:
    origin_url = ""
facts = {
    "is_repository": inside,
    "current_branch": current,
    "default_branch": "main" if "main" in branches else "master" if "master" in branches else "",
    "commit_count": commits,
    "branches": branches,
    "merge_count": merges,
    "repository_slug": slug,
}
```

Retain the outer unavailable-Git handling from Task 5 for all required Git history commands.

```python
# src/repoproof/collectors/github.py
import httpx
from repoproof.collectors.base import AuditContext, collector_provenance
from repoproof.domain import Evidence, EvidenceState
from repoproof.github import GitHubGateway
from repoproof.profile.models import Profile

class GitHubCollector:
    name = "github"

    def __init__(self, gateway: GitHubGateway, slug: str | None) -> None:
        self.gateway = gateway
        self.slug = slug

    def collect(self, context: AuditContext, profile: Profile) -> tuple[Evidence, ...]:
        if context.offline or not self.slug:
            return (Evidence("github:repository", "github_repository", ".",
                EvidenceState.UNAVAILABLE, {"reason": "offline_or_no_origin", "runtime_error": False},
                collector_provenance(context, self.name)),)
        owner, repo = self.slug.split("/", 1)
        try:
            repository = self.gateway.repository(owner, repo)
            facts = {
                "default_branch": repository.get("default_branch"),
                "merged_pull_requests": self.gateway.merged_pull_request_count(owner, repo),
                "has_release": self.gateway.has_release(owner, repo),
                "latest_actions_status": self.gateway.latest_actions_status(owner, repo),
                "runtime_error": False,
            }
            state = EvidenceState.AVAILABLE
        except LookupError:
            facts = {"reason": "token_missing", "runtime_error": False}
            state = EvidenceState.UNAVAILABLE
        except (httpx.HTTPError, ValueError):
            facts = {"reason": "network_or_auth_error", "runtime_error": True}
            state = EvidenceState.UNAVAILABLE
        finally:
            self.gateway.close()
        return (Evidence("github:repository", "github_repository", ".", state, facts,
            collector_provenance(context, self.name)),)
```

- [ ] **Step 6: Preserve local results and force exit 3 only for remote runtime failure**

Extend `build_report(..., runtime_failed: bool = False)` with this exit calculation:

```python
exit_code = (
    ExitCode.RUNTIME if runtime_failed else
    ExitCode.FINDINGS if any(f.status is FindingStatus.FAIL for f in ordered) else
    ExitCode.OK
)
```

Before calling `build_report`, calculate:

```python
runtime_failed = any(bool(item.facts.get("runtime_error", False)) for item in evidence)
diagnostics = ("github: remote evidence unavailable",) if runtime_failed else ()
```

Use the resulting values in the only report construction call:

```python
findings = evaluate(profile, evidence)
return build_report(
    profile, root, findings, diagnostics, timings, snapshot_at,
    runtime_failed=runtime_failed,
)
```

Extend the Task 9 dependency type and orchestration with:

```python
# additions to src/repoproof/app.py
from collections.abc import Callable

@dataclass(frozen=True, slots=True)
class AppDependencies:
    collectors: Mapping[str, Collector]
    clock: Callable[[], datetime]
    monotonic_ns: Callable[[], int]
    github_collector_factory: Callable[[str | None], Collector] | None = None

# inside run_audit, replace the collector loop with:
selected = required_collector_names(profile, request.offline)
for name in (item for item in selected if item != "github"):
    collector = dependencies.collectors.get(name)
    if collector is None:
        continue
    started = dependencies.monotonic_ns()
    evidence.extend(collector.collect(context, profile))
    timings[name] = (dependencies.monotonic_ns() - started) // 1_000_000

if "github" in selected and dependencies.github_collector_factory is not None:
    git_evidence = next((item for item in evidence if item.kind == "git_history"), None)
    slug = str(git_evidence.facts["repository_slug"]) if (
        git_evidence and git_evidence.facts.get("repository_slug")
    ) else None
    collector = dependencies.github_collector_factory(slug)
    started = dependencies.monotonic_ns()
    evidence.extend(collector.collect(context, profile))
    timings["github"] = (dependencies.monotonic_ns() - started) // 1_000_000
```

Replace `default_dependencies` with:

```python
def default_dependencies() -> AppDependencies:
    import httpx
    import keyring
    from repoproof import __version__
    from repoproof.collectors.github import GitHubCollector
    from repoproof.credentials import CredentialStore
    from repoproof.github import GitHubGateway

    def github_factory(slug: str | None) -> Collector:
        gateway = GitHubGateway(
            CredentialStore(keyring.get_keyring()),
            httpx.Client(headers={"User-Agent": f"RepoProof/{__version__}"}),
        )
        return GitHubCollector(gateway, slug)

    return AppDependencies({
        "files": FileCollector(), "markdown": MarkdownCollector(), "ci": CICollector(),
        "distribution": DistributionCollector(), "git": GitCollector(), "secrets": SecretCollector(),
    }, lambda: datetime.now(timezone.utc), monotonic_ns, github_factory)
```

This factory is called only when `required_collector_names` selected `github`; `--offline`
therefore creates neither `GitHubGateway` nor `httpx.Client`.

- [ ] **Step 7: Verify 401/403 redaction, timeout, missing Token, and successful evidence**

Run: `python -m pytest tests/unit/test_github.py tests/unit/collectors/test_github.py tests/integration/test_remote_degradation.py -q`

Run: `python -m pytest -q`

Expected: all tests pass; response headers/body and Token are absent from errors; missing Token yields SKIP without exit 3; timeout and HTTP failures preserve local findings and force exit 3.

- [ ] **Step 8: Commit optional remote evidence**

```bash
git add src/repoproof/github.py src/repoproof/collectors/github.py src/repoproof/collectors/git.py src/repoproof/app.py src/repoproof/reporting/model.py tests/unit/test_github.py tests/unit/collectors/test_github.py tests/integration/test_remote_degradation.py
git commit -m "feat: add optional sanitized GitHub evidence"
```

---

### Task 12: Prove acceptance behavior with public fixtures, security regressions, and a benchmark

**Files:**
- Create: `examples/compliant-repo/` fixture tree
- Create: `examples/noncompliant-repo/` fixture tree
- Create: `tests/e2e/test_examples.py`
- Create: `tests/e2e/test_report_parity.py`
- Create: `tests/e2e/test_non_disclosure.py`
- Create: `tests/unit/test_properties.py`
- Create: `tests/performance/test_large_repository.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: installed CLI and all application boundaries.
- Produces: executable acceptance evidence for AC-01, AC-04–09, AC-11–13.

- [ ] **Step 1: Add deterministic compliant and noncompliant fixture manifests**

```text
examples/compliant-repo/
├── .github/workflows/release.yml
├── .gitlab-ci.yml
├── AGENT_LOG.md
├── Makefile
├── PLAN.md
├── README.md
├── REFLECTION.md
├── SPEC.md
├── SPEC_PROCESS.md
├── pyproject.toml
└── repoproof.spec

examples/noncompliant-repo/
├── README.md
└── src/app.py
```

Use this exact compliant GitLab job:

```yaml
unit-test:
  image: python:3.12
  script:
    - python -m pytest
```

Use these exact README headings:

```markdown
# Fixture
## 项目简介
## 安装
## 运行
## 测试
## 分发
## 目录结构
## 安全边界
## 已知限制
```

- [ ] **Step 2: Write failing CLI and semantic parity acceptance tests**

```python
# tests/e2e/test_examples.py
import json
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

ROOT = Path(__file__).parents[2]

def test_compliant_fixture_is_auditable_without_network() -> None:
    result = CliRunner().invoke(app, [
        "audit", str(ROOT / "examples/compliant-repo"), "--profile", "ai4se-b",
        "--offline", "--format", "json",
    ])
    assert result.exit_code in (0, 1)
    assert '"report_schema": 1' in result.stdout
    assert "network" not in result.stderr.casefold()

def test_noncompliant_fixture_has_failures() -> None:
    result = CliRunner().invoke(app, [
        "audit", str(ROOT / "examples/noncompliant-repo"), "--offline",
        "--format", "json",
    ])
    assert result.exit_code == 1
    assert '"status": "FAIL"' in result.stdout

def test_repeated_audits_are_semantically_identical() -> None:
    repository = ROOT / "examples/noncompliant-repo"
    runner = CliRunner()
    first = json.loads(runner.invoke(
        app, ["audit", str(repository), "--offline", "--format", "json"]
    ).stdout)
    second = json.loads(runner.invoke(
        app, ["audit", str(repository), "--offline", "--format", "json"]
    ).stdout)
    first.pop("generated_at")
    second.pop("generated_at")
    first.pop("timings_ms")
    second.pop("timings_ms")
    assert first == second
```

```python
# tests/e2e/test_report_parity.py
import json
import re
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

def test_json_and_html_have_identical_finding_identity(tmp_path: Path) -> None:
    repository = Path(__file__).parents[2] / "examples/noncompliant-repo"
    output = tmp_path / "reports"
    output.mkdir()
    result = CliRunner().invoke(app, ["audit", str(repository), "--offline",
        "--format", "json", "--format", "html", "--output", str(output)])
    assert result.exit_code == 1
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    html = (output / "report.html").read_text(encoding="utf-8")
    json_pairs = {(item["rule_id"], item["status"]) for item in payload["findings"]}
    html_pairs = set(re.findall(r'data-rule-id="([^"]+)" data-status="([^"]+)"', html))
    assert json_pairs == html_pairs
```

- [ ] **Step 3: Write the complete observable-output canary regression**

```python
# tests/e2e/test_non_disclosure.py
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

CANARY = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"

def test_canary_is_absent_from_console_json_html_and_errors(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "leak.txt").write_text(f"token={CANARY}\n", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    result = CliRunner().invoke(app, ["audit", str(repository), "--offline",
        "--format", "console", "--format", "json", "--format", "html",
        "--output", str(reports), "--verbose", "--no-color"])
    observed = result.stdout + result.stderr
    observed += (reports / "report.json").read_text(encoding="utf-8")
    observed += (reports / "report.html").read_text(encoding="utf-8")
    assert CANARY not in observed
    assert "<redacted>" in observed
    assert "fingerprint" in observed
```

- [ ] **Step 4: Add property tests for path containment and deterministic ordering**

```python
# tests/unit/test_properties.py
from pathlib import Path
import pytest
from hypothesis import given, strategies as st
from repoproof.errors import UsageFailure
from repoproof.security import resolve_under_root

@given(st.lists(st.sampled_from(["..", "child"]), min_size=1, max_size=8))
def test_resolved_profile_paths_never_escape(tmp_path: Path, parts: list[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    candidate = "/".join(parts + ["file.txt"])
    if ".." in parts:
        with pytest.raises(UsageFailure):
            resolve_under_root(root, candidate)
    else:
        assert resolve_under_root(root, candidate).is_relative_to(root.resolve())
```

- [ ] **Step 5: Add the marked 10,000-file performance acceptance test**

```python
# tests/performance/test_large_repository.py
from pathlib import Path
from time import perf_counter
import pytest
from repoproof.collectors.base import AuditContext
from repoproof.collectors.files import FileCollector
from repoproof.profile.loader import load_profile

@pytest.mark.performance
def test_ten_thousand_file_inventory_finishes_within_fifteen_seconds(tmp_path: Path) -> None:
    for index in range(10_000):
        (tmp_path / f"file-{index:05}.txt").write_text("x", encoding="utf-8")
    started = perf_counter()
    evidence = FileCollector().collect(AuditContext(tmp_path, True), load_profile("ai4se-b"))
    elapsed = perf_counter() - started
    assert len(evidence[0].facts["paths"]) == 10_000
    assert elapsed < 15.0
```

Replace the pytest configuration with:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers --strict-config -m 'not performance'"
markers = ["performance: benchmark excluded from the default suite"]
```

Add this exact Make target and include `performance` in `.PHONY`:

```make
performance:
	python -m pytest tests/performance -m performance -q
```

- [ ] **Step 6: Run all acceptance and security checks**

Run: `python -m pytest tests/e2e tests/unit/test_properties.py -q`

Run: `python -m pytest tests/performance -m performance -q`

Run: `python -m pytest -q`

Expected: all commands exit 0; benchmark reports under 15 seconds on the documented machine; canary never appears in observable output.

- [ ] **Step 7: Commit acceptance fixtures and tests**

```bash
git add examples tests/e2e tests/unit/test_properties.py tests/performance pyproject.toml Makefile
git commit -m "test: prove RepoProof acceptance and security behavior"
```

---

### Task 13: Add dual CI, deterministic Windows packaging, and Release automation

**Files:**
- Create: `.gitlab-ci.yml`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `repoproof.spec`
- Create: `scripts/write_checksum.ps1`
- Create: `tests/unit/test_delivery_config.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `make verify`, installed `repoproof` entry point, public compliant fixture.
- Produces: AC-14–18 automation and artifacts named `repoproof-<version>-windows-x86_64.exe` plus `.sha256`.

- [ ] **Step 1: Write failing static delivery-config tests**

```python
# tests/unit/test_delivery_config.py
from pathlib import Path
import yaml

ROOT = Path(__file__).parents[2]

def test_gitlab_has_exact_unit_test_job() -> None:
    config = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    assert "unit-test" in config
    assert config["unit-test"]["script"] == [
        'python -m pip install -e ".[dev]"',
        "python -m pytest",
    ]

def load_workflow(name: str) -> dict[str, object]:
    return yaml.load(
        (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )

def test_ci_workflow_has_required_executable_structure() -> None:
    config = load_workflow("ci.yml")
    verify = config["jobs"]["verify"]
    assert verify["strategy"]["matrix"]["python-version"] == ["3.12", "3.13"]
    commands = [step["run"] for step in verify["steps"] if "run" in step]
    assert commands == [
        'python -m pip install -e ".[dev]"',
        "python -m ruff check src tests",
        "python -m mypy src",
        "python -m pytest",
    ]

def test_release_workflow_is_tag_only_and_smoke_tests_windows_artifact() -> None:
    config = load_workflow("release.yml")
    assert config["on"]["push"]["tags"] == ["v*"]
    build = config["jobs"]["build"]
    assert build["runs-on"] == "windows-latest"
    script = next(step["run"] for step in build["steps"] if "Move-Item" in step.get("run", ""))
    assert '& "dist/$name" version' in script
    assert '& "dist/$name" audit examples/compliant-repo --offline --format json' in script
```

- [ ] **Step 2: Run static delivery tests and verify RED**

Run: `python -m pytest tests/unit/test_delivery_config.py -q`

Expected: FAIL because CI and packaging files do not exist.

- [ ] **Step 3: Add GitLab and GitHub verification workflows**

```yaml
# .gitlab-ci.yml
unit-test:
  image: python:3.12
  script:
    - python -m pip install -e ".[dev]"
    - python -m pytest
```

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check src tests
      - run: python -m mypy src
      - run: python -m pytest
```

- [ ] **Step 4: Add PyInstaller configuration and checksum script**

```python
# repoproof.spec
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = collect_submodules("keyring.backends")
datas = collect_data_files("repoproof.profile")

a = Analysis(
    ["src/repoproof/__main__.py"],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="repoproof", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True,
)
```

```powershell
# scripts/write_checksum.ps1
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Output
)
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
$name = Split-Path -Leaf $Path
Set-Content -LiteralPath $Output -Value "$hash  $name" -Encoding ascii -NoNewline
```

- [ ] **Step 5: Add tag-triggered Windows build, smoke test, and Release**

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install -e ".[dev]"
      - run: python -m pytest
      - run: python -m PyInstaller --clean --noconfirm repoproof.spec
      - shell: pwsh
        run: |
          $version = "${{ github.ref_name }}".TrimStart("v")
          $name = "repoproof-$version-windows-x86_64.exe"
          Move-Item -LiteralPath dist/repoproof.exe -Destination "dist/$name"
          & "dist/$name" version
          & "dist/$name" audit examples/compliant-repo --offline --format json
          ./scripts/write_checksum.ps1 -Path "dist/$name" -Output "dist/$name.sha256"
      - uses: actions/upload-artifact@v4
        with:
          name: repoproof-windows-x86_64
          path: |
            dist/repoproof-*-windows-x86_64.exe
            dist/repoproof-*-windows-x86_64.exe.sha256
      - uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            dist/repoproof-*-windows-x86_64.exe
            dist/repoproof-*-windows-x86_64.exe.sha256
```

- [ ] **Step 6: Build and smoke-test locally, then verify workflow files**

Run: `python -m pytest tests/unit/test_delivery_config.py -q`

Run: `python -m PyInstaller --clean --noconfirm repoproof.spec`

Run on Windows: `.\dist\repoproof.exe version`

Run on Windows: `.\dist\repoproof.exe audit examples\compliant-repo --offline --format json`

Expected: static tests pass; executable prints the package version and completes fixture audit with exit 0 or 1 according to documented non-blocking Git-process warnings.

- [ ] **Step 7: Commit delivery automation**

```bash
git add .gitlab-ci.yml .github/workflows repoproof.spec scripts/write_checksum.ps1 tests/unit/test_delivery_config.py pyproject.toml
git commit -m "ci: verify package and publish Windows releases"
```

---

### Task 14: Complete user documentation, reflection, and traceable process evidence

**Files:**
- Create: `README.md`
- Create: `REFLECTION.md`
- Create: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `SPEC_PROCESS.md`
- Create: `tests/unit/test_course_documents.py`

**Interfaces:**
- Consumes: final CLI behavior, limitations, commit hashes from Tasks 1–13.
- Produces: AC-19/20 documentation and a root execution ledger in which every completed task has its actual 7–40 hexadecimal feature commit hash.

- [ ] **Step 1: Write failing course-document tests**

```python
# tests/unit/test_course_documents.py
import json
from pathlib import Path
from typer.testing import CliRunner
from repoproof.cli import app

ROOT = Path(__file__).parents[2]

def test_course_documents_pass_the_bundled_profile() -> None:
    result = CliRunner().invoke(app, [
        "audit", str(ROOT), "--profile", "ai4se-b", "--offline",
        "--format", "json", "--no-color",
    ])
    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    by_rule = {finding["rule_id"]: finding["status"] for finding in payload["findings"]}
    assert by_rule["docs.required"] == "PASS"
    assert by_rule["readme.sections"] == "PASS"
    assert by_rule["plan.commit-evidence"] == "PASS"
    assert by_rule["ci.gitlab-unit-test"] == "PASS"
```

- [ ] **Step 2: Run documentation tests and verify RED**

Run: `python -m pytest tests/unit/test_course_documents.py -q`

Expected: FAIL because README, REFLECTION, and root PLAN are not complete.

- [ ] **Step 3: Write README with exact runnable commands and security boundaries**

README must contain these concrete sections and commands:

```markdown
## 项目简介
RepoProof 是离线优先、默认只读的仓库发布前审计 CLI。

## 安装
python -m pip install -e .

## 运行
repoproof audit --profile ai4se-b --offline .
repoproof audit . --format json --output report.json
repoproof audit . --format html --output report.html
repoproof auth login

## 测试
python -m pip install -e ".[dev]"
make verify
python -m pytest tests/performance -m performance -q

## 分发
从 GitHub Release 下载 `repoproof-<version>-windows-x86_64.exe` 及同名
`.sha256` 文件，使用 `Get-FileHash -Algorithm SHA256` 核对。1.0 未进行
Authenticode 签名，Windows SmartScreen 可能显示警告；也可按“安装”从源码运行。

## 目录结构
说明 `src/repoproof`、`tests`、`examples`、`docs/superpowers`、CI 和打包文件职责。

## 安全边界
说明只读默认、显式报告写入、路径围栏、安全 YAML、无 LLM/代码执行/上传、
Secret 脱敏、Token 仅存 OS keyring、远程功能按需启用。

## 已知限制
说明静态检查不证明反思质量或 TDD 顺序、远程历史可能不完整、Secret 检测可能
误报、1.0 只发布未签名 Windows x64 二进制。
```

- [ ] **Step 4: Write an evidence-based reflection**

`REFLECTION.md` must contain these headings and cite concrete repository evidence:

```markdown
# RepoProof 项目反思
## 需求取舍
## 架构与确定性
## 安全与凭据治理
## TDD 与评审证据
## CI、分发与限制
## 如果继续迭代
```

Under each heading, cite at least one file, test name, commit hash, or CI run. Explain why the
project chose a general policy engine with bundled `ai4se-b`, why it did not use LLM/WebUI,
how non-disclosure tests changed the design, and which static checks remain intentionally modest.

- [ ] **Step 5: Create and populate the root execution ledger**

Use this exact table shape in `PLAN.md`; begin with pending rows and replace the final two cells
with `completed` and the real feature commit from Tasks 1–13 only after each commit exists:

```markdown
# RepoProof Execution Plan

Canonical implementation steps:
`docs/superpowers/plans/2026-07-29-repoproof-implementation.md`.

| Task | Deliverable | Status | Evidence commit |
|---|---|---|---|
| 1 | Package and domain contract | pending | not applicable until completion |
| 2 | Profile schema and bundled policy | pending | not applicable until completion |
```

For every completed row, obtain the feature hash with `git log --format="%h %s" --reverse`,
match its exact commit subject from the task's commit step, and record that returned hash.

- [ ] **Step 6: Record factual Superpowers, TDD, review, and human-approval evidence**

Append dated entries to `AGENT_LOG.md` for:

```text
- skill invoked and why
- test command and observed RED failure
- implementation command and observed GREEN result
- spec compliance review result
- code quality review result
- feature commit hash
- user action only when human intervention actually occurred
```

Update `SPEC_PROCESS.md` with the approved specification commit, plan commit, implementation
branch/PR, any requirement clarifications, and links to CI/Release evidence. Do not invent a
conversation, approval, RED result, review, PR, or CI run that did not occur.

- [ ] **Step 7: Verify documentation and self-audit the repository**

Run: `python -m pytest tests/unit/test_course_documents.py -q`

Run: `repoproof audit --profile ai4se-b --offline --format json --output build/self-audit.json .`

Run: `make verify`

Expected: document tests and full verification pass; self-audit has no `FAIL`, and any `WARN`/`SKIP`
is explained in README or REFLECTION without changing objective evidence.

- [ ] **Step 8: Commit course documentation**

```bash
git add README.md REFLECTION.md PLAN.md AGENT_LOG.md SPEC_PROCESS.md tests/unit/test_course_documents.py
git commit -m "docs: complete RepoProof delivery evidence"
```

---

### Task 15: Perform final review, merge through PR, tag 1.0.0, and verify the public Release

**Files:**
- Modify: `src/repoproof/__init__.py`
- Modify: `pyproject.toml`
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `SPEC_PROCESS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all AC-01–20, repository remote `origin`, GitHub CLI authentication.
- Produces: reviewed main-branch commit, tag `v1.0.0`, public GitHub Release URL, Windows x64 executable, checksum, and final evidence links.

- [ ] **Step 1: Set version 1.0.0 and write a failing version-consistency test**

```python
# tests/unit/test_delivery_config.py (release behavior addition)
from importlib.metadata import version as installed_version
from typer.testing import CliRunner
from repoproof.cli import app

def test_installed_cli_reports_release_version() -> None:
    result = CliRunner().invoke(app, ["version"], color=False)
    assert result.exit_code == 0
    assert installed_version("repoproof") == "1.0.0"
    assert result.stdout == "repoproof 1.0.0\n"
```

Run: `python -m pytest tests/unit/test_delivery_config.py::test_installed_cli_reports_release_version -q`

Expected: FAIL because both current versions are `0.1.0`.

- [ ] **Step 2: Update both version sources and verify GREEN**

Set `src/repoproof/__init__.py` to:

```python
__version__ = "1.0.0"
```

Set `project.version = "1.0.0"` in `pyproject.toml`.

Run: `python -m pip install -e .`

Run: `python -m pytest tests/unit/test_delivery_config.py::test_installed_cli_reports_release_version -q`

Expected: PASS.

- [ ] **Step 3: Run the complete fresh verification matrix**

Run: `git diff --check`

Run: `python -m ruff check src tests`

Run: `python -m mypy src`

Run: `python -m pytest`

Run: `python -m pytest tests/performance -m performance -q`

Run: `python -m PyInstaller --clean --noconfirm repoproof.spec`

Run on Windows: `.\dist\repoproof.exe version`

Run on Windows: `.\dist\repoproof.exe audit examples\compliant-repo --offline --format json`

Expected: every command exits 0 except a documented fixture audit may exit 1 only if its JSON
contains no course-blocking FAIL and the reason is an intentionally unavailable Git process
condition; otherwise fix the fixture or implementation before proceeding.

- [ ] **Step 4: Invoke required review skills and resolve findings**

Use `superpowers:requesting-code-review` for spec compliance and code quality. If feedback is
received, use `superpowers:receiving-code-review`, reproduce each issue, add a failing regression
test, implement the smallest fix, rerun the focused and full suites, and record the resulting
commit in `PLAN.md` and `AGENT_LOG.md`.

- [ ] **Step 5: Commit the release candidate**

```bash
git add src/repoproof/__init__.py pyproject.toml tests/unit/test_delivery_config.py PLAN.md AGENT_LOG.md SPEC_PROCESS.md README.md
git commit -m "release: prepare RepoProof 1.0.0"
```

Record the real hash in the completed Task 15 PLAN row before the final evidence-only commit.

- [ ] **Step 6: Publish the implementation branch and open a PR**

Use `superpowers:finishing-a-development-branch` to inspect the clean worktree and integration
options, then use the connected GitHub workflow to push and open a non-draft PR:

```bash
git push -u origin agent/implementation-repoproof
gh pr create --base main --head agent/implementation-repoproof \
  --title "feat: deliver RepoProof 1.0" \
  --body "Implements SPEC.md and AC-01 through AC-20. Includes offline audit, safe optional GitHub evidence, credential governance, CI, tests, and Windows Release automation."
gh pr checks --watch
```

Expected: the PR exists, CI passes for Python 3.12 and 3.13, and the PR contains the focused
commit history recorded in `PLAN.md`.

- [ ] **Step 7: Merge only after green CI, then tag the exact merged commit**

```bash
gh pr merge --merge --delete-branch
git switch main
git pull --ff-only origin main
git tag -a v1.0.0 -m "RepoProof 1.0.0"
git push origin v1.0.0
```

Expected: `main` contains the reviewed merge commit and tag `v1.0.0` points to that commit.

- [ ] **Step 8: Verify the Release workflow and downloaded artifacts**

```bash
gh run list --workflow Release --limit 1
gh run watch "$(gh run list --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId')"
gh release view v1.0.0 --json url,assets
gh release download v1.0.0 --pattern "repoproof-1.0.0-windows-x86_64.exe*" --dir build/release-check
```

On Windows, compare the downloaded checksum and run:

```powershell
$expected = (Get-Content -LiteralPath build/release-check/repoproof-1.0.0-windows-x86_64.exe.sha256).Split()[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath build/release-check/repoproof-1.0.0-windows-x86_64.exe).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "checksum mismatch" }
& build/release-check/repoproof-1.0.0-windows-x86_64.exe version
& build/release-check/repoproof-1.0.0-windows-x86_64.exe audit examples/compliant-repo --offline --format json
```

Expected: the Release exposes the exe and checksum, hashes match, version prints `1.0.0`, and
the downloaded binary completes the fixture audit.

- [ ] **Step 9: Record final URLs and run the acceptance checklist one last time**

Add the actual PR URL, passing CI run URL, Release URL, tag commit, artifact names, and checksum
verification result to `AGENT_LOG.md`, `SPEC_PROCESS.md`, `README.md`, and the Task 15 row of
`PLAN.md`. Commit and push this evidence-only update to `main` only through a final PR; do not
rewrite the `v1.0.0` tag. If the course requires all evidence inside the tagged source archive,
record these URLs before tagging instead and use the Release workflow URL available from the
pre-created draft Release.

Run: `repoproof audit --profile ai4se-b --offline .`

Run: `git status --short --branch`

Expected: self-audit has no FAIL, worktree is clean, local `main` matches `origin/main`, and the
GitHub Release URL is ready for submission.

---

## Acceptance coverage map

| Acceptance | Implemented by | Verified by |
|---|---|---|
| AC-01 offline audit | Tasks 3–9 | `tests/e2e/test_examples.py` |
| AC-02 bundled course checks | Tasks 2, 4–7 | profile loader/rule tests and self-audit |
| AC-03 invalid profiles exit 2 | Task 2 | profile unit and CLI integration tests |
| AC-04 deterministic semantics | Tasks 7–9 | `test_determinism.py` and report parity |
| AC-05 states/exit codes | Tasks 1, 7, 9, 11 | domain, rule matrix, CLI degradation tests |
| AC-06 reporter parity | Task 8, 12 | report unit tests and E2E parity |
| AC-07 safe self-contained HTML | Task 8 | `test_html_is_escaped_and_self_contained` |
| AC-08 non-disclosure | Tasks 6, 8, 10–12 | canary and auth regression tests |
| AC-09 path/symlink containment | Tasks 3, 12 | security, collector, and Hypothesis tests |
| AC-10 credential lifecycle | Task 10 | fake-keyring unit and CLI tests |
| AC-11 missing Token/offline SKIP | Tasks 7, 11 | remote degradation tests |
| AC-12 network failure exit 3 | Task 11 | partial-failure integration test |
| AC-13 10,000 files under 15s | Task 12 | marked performance test |
| AC-14 unified tests | Tasks 1, 12 | `make verify` and CI |
| AC-15 GitLab `unit-test` | Task 13 | delivery config test |
| AC-16 push CI | Task 13 | GitHub Actions CI run |
| AC-17 packaged exe smoke | Tasks 13, 15 | Windows runner and downloaded binary |
| AC-18 Release assets/docs | Tasks 13–15 | Release API, checksum, README |
| AC-19 README sections | Task 14 | course-document test |
| AC-20 process artifacts | Tasks 14–15 | course-document test and final self-audit |

## Plan self-review checklist

- [x] Every SPEC section and AC-01–20 maps to an implementation task and objective verification.
- [x] No task introduces a seventh schema-1 rule type, LLM, WebUI, code-executing profile, plaintext Token fallback, or source upload.
- [x] Every producer/consumer uses the exact `Evidence`, `Finding`, `AuditReport`, `Profile`, `AuditContext`, and function names locked above.
- [x] Every task begins with a focused failing test, records the expected failure, implements the minimum behavior, reruns focused/full verification, and creates a focused commit.
- [x] No completed root `PLAN.md` item is marked complete without its actual feature commit hash.
- [x] No unresolved marker or unspecified future error/test instruction remains.
- [x] Release publication occurs only after fresh local verification, two-stage review, and green CI.

Self-review result on 2026-07-29: Tasks 1–15 are present exactly once; AC-01–20 are all
covered; all 240 Markdown code fences are balanced; the forbidden future-work language scan
returned zero matches; locked cross-task interfaces are present; `git diff --check` returned no
whitespace error.
