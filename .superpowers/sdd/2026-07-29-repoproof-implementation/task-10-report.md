# Task 10 Report — Keyring Credential Lifecycle

Baseline: `8ad8e20c79cc2ab4cbf0695769cefad14c8bebef`.

Implemented `CredentialStore` as an injected OS-keyring-only credential boundary and added
`repoproof auth login`, `status`, and `logout`. Host inputs are canonical DNS hostnames only;
login updates existing credentials and logout is idempotent. The CLI accepts no token option or
environment fallback, reads tokens through `getpass` only in a TTY, and reports only configured
state plus backend name.

Backend calls that can observe credentials return internal safe status values. Public
`UsageFailure`s are constructed only after the token-bearing frame has returned and the token
reference is cleared, so backend exceptions (including one whose text contains the token) do not
remain in the error cause, context, representation, or RepoProof traceback locals. The store's
explicit representation includes only the backend type name.

Focused TDD evidence:

- RED: `python -m pytest tests/unit/test_credentials.py tests/integration/test_cli_auth.py -q`
  failed at collection with the expected missing `repoproof.credentials` module.
- GREEN: the same focused command passed 3 tests.

Verification evidence:

- `python -m ruff check src tests`: passed.
- `python -m mypy src`: passed (28 source files).
- `python -m pytest -q`: 174 passed, 5 skipped.
- `git diff --check`: passed.

Concern: the actual OS keyring is intentionally not exercised by automated tests; the fake
backend validates the lifecycle and failure boundary without creating credentials or files.

## Fix round 1 — auth parse sanitization and status host

Click's default parser rejected an unexpected positional token before `auth_login` ran, and its
`UsageError` kept and rendered that raw argument. `auth login` now uses an extra-argument command
context, clears the captured values before constructing a generic interactive-only exit-2
diagnostic, and still does not declare or accept a token argument or option. `auth status` now
reports the normalized host alongside its configured state and backend.

Focused TDD evidence:

- RED: the two new CLI regressions failed: the extra token appeared in the parse error's
  representation/output, and status omitted `host: github.com` for `GitHub.COM.`.
- GREEN: `python -m pytest tests/integration/test_cli_auth.py -q` passed 3 tests.

Verification evidence:

- `python -m pytest tests/unit/test_credentials.py tests/integration/test_cli_auth.py -q`:
  5 passed.
- `python -m ruff check src tests`: passed.
- `python -m mypy src`: passed (28 source files).
- `python -m pytest -q`: 176 passed, 5 skipped.
