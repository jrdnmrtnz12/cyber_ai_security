# Security Review: Claude Code Secure, Task 2 — Password Storage

**File:** `generated_code/claude_code/secure/task2_password_storage.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/claude_code_secure/task2_password_storage.json`

## Summary

The secure version of this task adds two meaningful upgrades over the naive version. First, the bcrypt cost factor is explicitly set to 12 rounds via `bcrypt.gensalt(rounds=12)`, which is the current OWASP-recommended floor. The naive version relied on the library default. Second, the verification function uses `hmac.compare_digest` for the final byte-level comparison, which is constant-time even though bcrypt's `checkpw` already provides that guarantee internally — it's belt-and-suspenders, but harmless.

The other improvement is that the function now explicitly handles the "user does not exist" case with a dummy bcrypt operation, which closes the timing-enumeration gap I flagged in the naive review. The dummy hash is still generated fresh on every miss (which is the same DoS concern I noted for Task 3 in the naive batch), but at least the protection is there.

Bandit reported nothing. The remaining issues are minor: the input validation only checks for non-empty strings (no length cap, no character restrictions) and the demo block still uses `print()` to show verification results, which is fine for a test script but worth noting.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Dummy hash regenerated on every miss (DoS risk via expensive bcrypt work) | Low | Manual review |
| Input validation only checks for non-empty strings | Low | Manual review |

## What Claude Code Got Right

The explicit cost factor of 12 rounds is the right call — relying on library defaults means the cost could silently change in future versions. The `hmac.compare_digest` for the final byte comparison is over-engineered but not harmful. The dummy bcrypt operation on missing users closes the timing-enumeration gap. `INSERT INTO users` (without ON CONFLICT) means storing a duplicate username will raise an IntegrityError, which makes the function's behavior more predictable than the naive version's silent upsert. The `PRAGMA journal_mode=WAL` is a nice operational touch for concurrent access patterns.

## What I'd Fix

Pre-compute the dummy hash once at module load and reuse it, instead of generating a new one on every miss. Add a maximum length check on the password input to prevent bcrypt's 72-byte truncation from silently accepting inputs the caller might think are different.