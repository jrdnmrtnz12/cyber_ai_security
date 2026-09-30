# Security Review: Claude Code Naive, Task 2 — Password Storage

**File:** `generated_code/claude_code/naive/task2_password_storage.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/claude_code_naive/task2_password_storage.json`

## Summary

This file uses bcrypt for password hashing, which is one of the three currently recommended algorithms for password storage (alongside Argon2 and scrypt). bcrypt is older than Argon2 but still considered cryptographically sound, and the `bcrypt.checkpw` function performs constant-time comparison. The salt is generated per-password via `bcrypt.gensalt()` and embedded in the hash output.

Bandit reported nothing on this file and my manual review didn't find much either. The verification function returns `False` whether the user doesn't exist or the password is wrong, which prevents enumeration through differential return values. SQL queries are parameterized. The `INSERT ... ON CONFLICT DO UPDATE` pattern handles both new and existing users in a single statement, which is cleaner than separate insert and update paths.

The one structural concern I'd flag is that there's no constant-time check when the user doesn't exist. The function returns `False` immediately without doing any bcrypt work, which means an attacker measuring response time could distinguish between "user exists with wrong password" (slow, bcrypt runs) and "user doesn't exist" (fast, returns immediately). The Task 3 login endpoint actually handles this correctly, but this file doesn't. As a low-level utility this might be acceptable since the caller can add its own timing protection, but it's worth noting.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| No constant-time path for non-existent users (enumeration via timing) | Low | Manual review |
| No password complexity check at storage layer | Low | Manual review |
| Demo block uses `print()` of verification results | Low | Manual review |

## What Claude Code Got Right

bcrypt is a strong choice. The per-password salt is handled automatically by the library. Constant-time comparison is built into `checkpw`. Parameterized SQL throughout. The `ON CONFLICT DO UPDATE` pattern is elegant and avoids the race condition between checking for existence and inserting. The function signatures use type hints, which is a small touch but reads as professional.

## What I'd Fix

Add a constant-time path for the case where the user doesn't exist. The simplest approach is to run `bcrypt.checkpw(password_attempt.encode(), DUMMY_HASH)` and discard the result, which equalizes the work whether or not the user is found. The complexity check at the storage layer is debatable, but at minimum the function should refuse to store an empty-string password.