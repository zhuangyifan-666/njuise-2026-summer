# Task 6 report: non-disclosing secret evidence

## Delivered

- Added a strict UTF-8 YAML secret allowlist whose only entry identity is
  `rule_id`, repository-relative `path`, and an 8-hex fingerprint. It rejects
  unknown/raw-value fields, non-schema-1 input, oversized files, excessive YAML
  aliases, and unsafe/reparse-point allowlist paths with sanitized
  `UsageFailure` instances.
- Added `SecretCollector`, which reports only category, relative path, line,
  8-hex SHA-256 fingerprint, and matching allowlist rule IDs. It streams bounded
  reads, skips binary and oversized content, detects configured token/private-key/
  high-entropy/sensitive-filename categories, and stops with LIMITED evidence at
  the bounded match cap.
- Refactored Task 3's reviewed `scandir` implementation into `repository_files`.
  Both inventory and secret scanning now share ignore-file handling, root
  containment, symlink/junction/all-reparse-point rejection, deterministic
  ordering, candidate/byte limits, and deadline checks. This prior-file change
  was necessary to prevent Task 6 from introducing a weaker duplicate traversal.

## TDD evidence

- RED: before production modules existed, the exact focused Task 6 command
  failed at collection with missing `repoproof.allowlist` and
  `repoproof.collectors.secrets` modules (three collection errors).
- GREEN: `python -m pytest tests/unit/test_allowlist.py
  tests/unit/collectors/test_secrets.py
  tests/integration/collectors/test_secret_non_disclosure.py
  tests/integration/collectors/test_files.py -q` reported `20 passed, 4 skipped`.
- Security regression mutation: temporarily removing the post-open byte counter
  made `test_read_limit_is_enforced_even_when_file_metadata_is_stale` fail by
  reporting a token. Restoring the counter returned the test to GREEN.

## Fresh verification

- `python -m ruff check src tests` — clean.
- `python -m mypy src` — `Success: no issues found in 19 source files`.
- `python -m pytest -q` — `79 passed, 4 skipped`.
- `git diff --check` — clean (Git emitted only its expected line-ending warning
  for the pre-existing Windows worktree setting).

## Self-review

- Evidence and allowlist APIs never retain raw matched bytes/text; fingerprints
  are calculated immediately and exceptions are raised without raw parser or OS
  detail chaining.
- Every collector candidate comes through the shared bounded traversal, and the
  scanner independently rechecks containment/reparse safety before opening.
- Per-rule categories, exclusion patterns, entropy thresholds, and allowlist
  rule/path/fingerprint identity are all considered. Allowlisting marks evidence;
  it does not remove a match.
- Read size is enforced both from inventory metadata and during actual I/O, which
  closes a size-change race. Long physical lines are processed in fixed-size
  fragments with a bounded overlap.

## Concerns

No known correctness or security blockers. As with Task 3's existing filesystem
boundary, a hostile concurrent filesystem can still race a check between the
final safety check and `open` on platforms without a no-follow open primitive;
the implementation rechecks immediately before opening and never intentionally
follows a discovered link or reparse point.

## Formal review round 1/5

### Remediated findings

- **C1 / I4:** allowlist file I/O, UTF-8 decoding, YAML scanning/composition/
  parsing, structural validation, and Pydantic validation are contained in a
  raw-bearing helper. The helper catches parser/resource failures and returns a
  status/model only after clearing raw references. It uses a verified regular
  handle, an actual-read 1 MiB cap, descriptor revalidation, alias, depth,
  node, and container-size limits. Public failures are raised by a non-raw
  wrapper without cause/context.
- **C2:** raw secret scanning is now a status-returning helper. It catches
  timeout, reader, and classifier failures while raw fragments/windows/tails
  exist, clears them, and lets the outer non-raw collector produce a sanitized
  `RuntimeFailure`.
- **I3:** added handle-based regular-file opening. POSIX uses component-wise
  `openat` with `O_NOFOLLOW`; Windows uses `CreateFileW` with final reparse-point
  opening, opened-handle final-path containment, and fail-closed reparse/type
  checks before content reads. A final-link regression verifies no handle is
  returned for an external link.
- **I5 / I7:** scanner size limits are checked from the opened descriptor and
  revalidated after streaming. The initial binary probe is the first classified
  chunk; it is not seeked/reread, and actual read bytes never exceed the budget.
- **I6:** chunk processing defers unstable suffix matches in a bounded overlap
  and classifies final physical-line/EOF fragments once. Maximum token and
  split private-key/assignment regressions prevent truncation or duplicates.
- **I8:** high-entropy classification carries the exact threshold-triggered rule
  IDs; `allowlisted_for` can credit only those IDs, in canonical order.

### Review TDD evidence

- RED: four initial focused regressions failed against the prior implementation:
  allowlist raw values remained in traceback frames (including deep nesting), a
  classifier exception escaped directly, and stale inventory metadata reported
  an oversized opened file.
- GREEN: after the helper/handle changes,
  `python -m pytest tests/unit/test_security.py tests/unit/test_allowlist.py
  tests/unit/collectors/test_secrets.py
  tests/integration/collectors/test_secret_non_disclosure.py
  tests/integration/collectors/test_files.py -q` reported `33 passed, 5 skipped`.
  The added split private-key/assignment boundary test then reported `1 passed`.
- Final fresh verification is recorded below after the complete command set.

### Formal review final verification

- `python -m pytest tests/unit/test_security.py tests/unit/test_allowlist.py
  tests/unit/collectors/test_secrets.py
  tests/integration/collectors/test_secret_non_disclosure.py
  tests/integration/collectors/test_files.py -q` — `34 passed, 5 skipped`.
- `python -m ruff check src tests` — clean.
- `python -m mypy src` — `Success: no issues found in 19 source files`.
- `python -m pytest -q` — `89 passed, 5 skipped`.
- `git diff --check` — clean (only expected Git CRLF conversion notices).

### Review concerns

The two explicitly deferred Minor report/history findings were not changed in
this round. Windows path handling is covered by `CreateFileW` final-component
reparse opening and final-handle containment; if those handle queries fail the
operation fails closed before bytes are read. Parent-component changes are
preflight-reparse-checked and final-handle-contained; no content is read from a
replaced target before that containment validation.

## Formal review round 2/5

- Allowlist cleanup now clears raw bytes/text/parser references before an
  exception-contained close operation, so a close failure cannot replace a safe
  result with a raw traceback.
- Raw scanning catches `BaseException` categories, converts interruption to a
  safe status, clears raw buffers, and re-raises `KeyboardInterrupt` only from
  the non-raw collector frame.
- Safe-open failures now carry sanitized `missing`, `unsafe`, or `operational`
  classes. The collector skips only missing/unsafe candidates and converts
  operational failures to a sanitized runtime failure; allowlist failures remain
  sanitized usage failures without following an `exists()` fallback.
- Physical-line collection replaces fixed overlap classification. Lines remain
  bounded by the configured per-file read budget and are classified only at
  newline/EOF. The raw helper receives remaining match capacity and stops before
  accumulating beyond it.

### Round 2 TDD evidence

- Focused regressions for raw close failure, keyboard interruption, and raw
  helper match capacity reported `3 passed`.
- The pre-change suite initially exposed missing-file classification on Windows
  after reason-class hardening; correcting non-following missing classification
  returned the existing secret collector regression to GREEN.
- Final round-2 verification: Task3+Task6 focused `37 passed, 5 skipped`;
  Ruff clean; mypy `Success: no issues found in 19 source files`; full suite
  `92 passed, 5 skipped`; `git diff --check` clean apart from expected CRLF
  notices.
