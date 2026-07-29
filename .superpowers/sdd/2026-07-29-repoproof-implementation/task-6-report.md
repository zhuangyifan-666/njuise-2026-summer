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
