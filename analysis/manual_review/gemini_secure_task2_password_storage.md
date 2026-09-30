# Security Review: Gemini Secure, Task 2 — Password Storage

**File:** `generated_code/gemini/secure/task2_password_storage.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_secure/task2_password_storage.json`

## Summary

This file is structurally similar to the naive version and doesn't change much. Bcrypt is still used for hashing with a per-password salt embedded in the hash output, `bcrypt.checkpw` is used for constant-time verification, and SQL queries are parameterized throughout. The code now separates `hash_password` from `register_user`, which improves modularity but doesn't change the security posture.

Bandit reported nothing on this file. My manual review surfaced the same issues that were present in the naive version. The `register_user` function still doesn't distinguish between "username already exists" and other database errors — both come back through the same `print` statement. There's no constant-time path for the "user does not exist" case in `verify_login`, so timing analysis could still distinguish missing users from wrong passwords. The bcrypt cost factor isn't explicitly set, so it relies on the library default.

The interesting comparison here is to Claude Code's secure Task 2, which made meaningful improvements over its naive version (explicit cost factor, dummy bcrypt operation for missing users). Gemini's secure Task 2 made essentially no changes from the naive version. The security-aware prompt didn't seem to prompt new defensive thinking on this file.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| No constant-time path for non-existent users | Low | Manual review |
| Bcrypt cost factor not explicitly specified | Low | Manual review |
| `register_user` conflates duplicate username with other DB errors | Low | Manual review |
| Hardcoded test credentials in demo block | Low | Manual review |

## What Gemini Got Right

Bcrypt is the right algorithm choice. Per-password salt is handled automatically. Verification uses `bcrypt.checkpw` for constant-time comparison. SQL queries are parameterized. The function signatures use type hints. The `IntegrityError` pattern lets the database constraint handle duplicates rather than a separate pre-check.

## What I'd Fix

Add a dummy bcrypt operation in the "user not found" path of `verify_login` so the response time is similar whether the user exists or not. Explicitly set the bcrypt cost factor (e.g., `bcrypt.gensalt(rounds=12)`) to avoid relying on library defaults. Distinguish between duplicate-username errors and other database failures in `register_user`.