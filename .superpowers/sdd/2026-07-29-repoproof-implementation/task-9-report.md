# Task 9 Report — Offline Audit CLI

Baseline: `7e9f7057979221ddca89467c25e517291a9b5ee8`.

Implemented the injected `AuditRequest` / `AppDependencies` orchestration boundary and the
`repoproof audit` command. The application creates one shared snapshot/context, runs only the
sorted required collectors, builds one canonical report, and fails safely when a required
collector is unavailable. The offline registry is local-only, so `--offline` never requests a
GitHub collector.

The CLI validates multi-file output routing before scanning, renders through the existing safe
console/JSON/HTML renderers, performs explicit report writes only after a complete audit through
the atomic writer, and maps usage/profile, runtime, findings, and passing outcomes to 2, 3, 1,
and 0 respectively. Unhandled exceptions receive a sanitized runtime diagnostic on stderr.

Focused TDD evidence:

- RED: the new focused suite failed at collection with the expected
  `ModuleNotFoundError: No module named 'repoproof.app'`.
- GREEN: the focused application, exit-boundary, output-routing, and minimal pass-exit tests
  passed: 5 tests.

Verification evidence:

- `python -m pytest -q`: 170 passed, 5 skipped.
- `python -m ruff check src tests`: passed.
- `python -m mypy src`: passed (27 source files).
- `git diff --check`: passed.

Concern: non-offline profiles that require an unimplemented remote GitHub collector currently
produce the controlled runtime exit 3 rather than silently skipping remote evidence. The offline
audit path required by this task remains fully local and does not access GitHub.

## Review fix round 1

Malformed profile errors no longer interpolate PyYAML or Pydantic exception text into a
`UsageFailure` remediation. The loader now returns stable generic profile/fix guidance and raises
without an exception cause, preventing parser `input_value` content from reaching CLI diagnostics.
The existing profile-validation test was adjusted to the safe generic contract, and one new audit
CLI regression verifies that a recognizable credential-format canary is absent from stdout, stderr,
and the captured exception representation while exit 2 and useful profile/fix guidance remain.

Verification: RED exposed the canary in Pydantic `input_value` text; GREEN passed the new regression.
The focused regression and current Task 9 audit tests passed, and the full suite passed with 171
tests and 5 skips. Ruff, mypy, and `git diff --check` also passed.

## Review fix round 2

The canary regression now traverses every reachable `__cause__` and `__context__` from the
`CliRunner` exception and rejects the canary, `ValidationError`, and parser `input_value` detail
at every node. RED showed that `raise ... from None` hid the error from normal display but retained
the graph `SystemExit → UsageFailure → ValidationError`.

`load_profile` now records only a fixed safe failure result while parser and validation handlers
are active, then raises `UsageFailure` after leaving those handlers. This detaches raw parser and
Pydantic exceptions instead of merely suppressing their displayed context.

Verification: the enhanced regression and the Task 9 audit suite passed (6 tests); full pytest
passed with 171 tests and 5 skips. Ruff, mypy, and `git diff --check` passed.
