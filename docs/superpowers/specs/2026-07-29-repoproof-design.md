# RepoProof Design

**Date:** 2026-07-29
**Status:** Approved in four design checkpoints
**Canonical course specification:** [`../../../SPEC.md`](../../../SPEC.md)

## Context

RepoProof converts delivery requirements into deterministic repository checks. Its primary users are students preparing course submissions and small teams preparing releases. It is a B-class application, not an autonomous agent: it has no LLM loop, no tool autonomy, and no agent framework.

The selected product approach is a general policy engine with a bundled `ai4se-b` profile. Two alternatives were rejected:

- a hard-coded course checklist was too narrow and looked like a one-off script;
- a security-first scanner would duplicate mature tools and displace the release-evidence problem.

## Product boundary

The primary command is:

```text
repoproof audit --profile ai4se-b .
```

RepoProof reads local repository evidence, evaluates predefined rule types, and renders console, JSON, or self-contained HTML reports. It does not modify the repository, upload source code, use an LLM, execute policy scripts, or provide a WebUI in version 1.0.

Audit outcomes are `PASS`, `WARN`, `FAIL`, and `SKIP`. Process exit codes are 0 for no FAIL, 1 for completed audit with FAIL, 2 for usage/profile errors, and 3 for repository, network, or internal runtime errors.

## Architecture

```text
CLI -> Audit Application Service -> Profile Loader
                              \-> Evidence Collectors
Profile + Evidence -> Rule Engine -> AuditReport -> Reporters
GitHub Collector -> Credential Store + HTTPS Gateway
```

### Components

1. **CLI:** parses commands and renders top-level errors.
2. **Profile module:** safely loads strict YAML into typed rules.
3. **Collectors:** gather file, Markdown, Git, CI, distribution, Secret, and optional GitHub evidence.
4. **Rule Engine:** pure evaluation from Profile + Evidence to Findings.
5. **Reporters:** render a single immutable AuditReport to console, JSON, and HTML.
6. **Credential Store / GitHub Gateway:** provide optional remote evidence without leaking Token material.

The domain model contains `Profile`, `Rule`, `Evidence`, `Finding`, and `AuditReport`. The domain layer has no filesystem, CLI, HTTP, keyring, or rendering dependency.

## Data flow

1. Resolve and validate the repository root.
2. Load and validate an internal or custom profile.
3. Determine which evidence kinds the profile needs.
4. Run applicable read-only Collectors.
5. Evaluate all rules with the pure Rule Engine.
6. Build one AuditReport with stable ordering and summary.
7. Render selected formats.
8. Return the documented exit code.

Remote evidence is opt-in. Offline rules continue to run when GitHub credentials or networking are unavailable.

## Security

- resolved paths must remain under the repository root;
- external symlinks are skipped;
- scan size, file count, process output, and network duration are bounded;
- YAML cannot construct objects or execute expressions;
- Git subprocesses use argument arrays and never invoke a shell;
- Secret matches are replaced by `<redacted>` and represented only by type, location, and a short SHA-256 fingerprint;
- GitHub Tokens are entered with hidden input and stored only in the operating-system keyring;
- no plaintext credential fallback is allowed;
- HTML escapes repository-controlled strings and has no JavaScript or remote assets.

## Error handling

Rule non-compliance is data, not an exception. Missing optional evidence produces SKIP. Invalid commands and policies exit 2. Repository I/O, required tool, network, and internal errors become redacted diagnostics and exit 3. A network error never discards completed local findings.

## Testing

Development follows test-first Red–Green–Refactor. The Rule Engine, profile models, exit codes, reporters, redaction, and path boundary are unit tested. Collectors use temporary filesystem and Git fixtures. Keyring and HTTP are injected fakes. CLI integration tests assert output and exit codes. Two repository fixtures provide end-to-end compliant and non-compliant cases. The PyInstaller executable runs smoke tests on a clean Windows runner.

Every implementation task receives two reviews in order:

1. specification compliance;
2. code quality.

## Performance and observability

Offline audits of repositories with up to 10,000 candidate files and 500 MiB must complete within 15 seconds on a standard four-core development machine. Individual reads are capped at 2 MiB. Verbose mode reports stage timings and skip reasons without file contents or credentials.

## Distribution

Version 1.0 ships through GitHub Release as an unsigned Windows x64 single executable plus SHA-256 checksum. GitHub Actions tests, type-checks, lints, builds, and smoke-tests the artifact. A `.gitlab-ci.yml` file includes the course-required `unit-test` job. README documents the unsigned state and possible SmartScreen warning.

## Approved checkpoints

1. Product boundary and main flow — approved by the student.
2. Architecture and module boundaries — approved by the student.
3. Rule semantics, error handling, and security boundary — approved by the student.
4. Technology, tests, performance, and distribution — approved by the student.
