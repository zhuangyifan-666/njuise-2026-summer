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
