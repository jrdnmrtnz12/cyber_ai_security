# Security Review: Gemini Naive, Task 2 — Password Storage

**File:** `generated_code/gemini/naive/task2_password_storage.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_naive/task2_password_storage.json`

## Summary

This is a solid password storage utility. Gemini used bcrypt with the recommended pattern: generate a salt with `bcrypt.gensalt()`, hash the password with `bcrypt.hashpw`, and verify with `bcrypt.checkpw`, which extracts the embedded salt and runs constant-time comparison automatically. SQL queries are parameterized throughout. The functions return `True`/`False` cleanly, and `verify_login` returns `False` whether the user doesn't exist or the password is wrong, which prevents enumeration through differential return values.

Bandit flagged the hardcoded test password `'P@ssw0rd123!'` in the demo block at the bottom. That's a fair catch in the sense that there's a literal password in the source code, but it's clearly demo material rather than a real credential — the file is meant to be run as a quick self-test. I'd note it as a Bandit false positive in the methodology rather than a real security issue.

My manual review didn't turn up much. The function `register_user` returns `True` or `False` based on whether the insert succeeded, but there's no way to distinguish "username taken" from "other database error" — both come back as `False`. That's not a security issue but it makes the function harder to use correctly. There's also no constant-time path for the "user does not exist" case, which means an attacker could potentially distinguish between "user exists with wrong password" (bcrypt runs, slow) and "user does not exist" (returns immediately, fast). Same issue I flagged for the Claude Code naive Task 2.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Hardcoded test password in demo block | Low | Bandit (likely false positive) |
| No constant-time path for non-existent users | Low | Manual review |
| `register_user` conflates "username taken" with "other DB error" | Low | Manual review |

## What Gemini Got Right

bcrypt is the correct algorithm choice. The salt is generated per-password and embedded in the hash output. Verification uses `bcrypt.checkpw`, which is constant-time. SQL queries are parameterized. The `try/except sqlite3.IntegrityError` pattern uses the database constraint to catch duplicates rather than doing a separate existence check first, which avoids a TOCTOU race. The functions are reasonably self-contained and easy to test.

## What I'd Fix

Add a dummy bcrypt operation in the "user not found" path so the response time is similar whether the user exists or not. Distinguish between "username already taken" and other database errors in the return value of `register_user`. Move the demo test credentials out of the production file or wrap them in an obvious `# DEMO ONLY` marker.