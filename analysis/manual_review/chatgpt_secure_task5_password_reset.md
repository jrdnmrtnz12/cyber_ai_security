# Security Review: ChatGPT Secure, Task 5 — Password Reset

**File:** `generated_code/chatgpt/secure/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/chatgpt_secure/task5_password_reset.json`

## Summary

The naive version of this task was already strong, but the secure version takes it further in ways that surprised me. The biggest change is that reset tokens are no longer stored in the database directly. Instead, the raw token gets generated with `secrets.token_urlsafe(32)`, then a SHA-256 hash of that token gets stored in a dedicated `password_reset_tokens` table. The hash is what's stored; the raw token only exists in the email link. This means even if an attacker compromises the database, they can't use the stored values to reset anyone's password.

The single-use enforcement is also more robust. The naive version cleared a token_id field after use, but the secure version uses a transactional `UPDATE ... WHERE used_at IS NULL AND expires_at > ?` pattern that only succeeds if the token is still valid at the moment of the update. If the update affects zero rows, the transaction rolls back and the user gets a generic error. That's atomic single-use enforcement that prevents a race condition where two simultaneous requests could both consume the same token.

Password validation is now multi-factor: length plus lowercase, uppercase, digit, and special character requirements. The new password is hashed with `generate_password_hash(password, method="scrypt")`, which explicitly chooses the algorithm instead of relying on library defaults.

Bandit reported nothing. The `print()` statement is still there in `send_password_reset_email`, but it's clearly marked as `[DEV ONLY]` and the function has a docstring explicitly saying not to log reset links in production. That's a real improvement over the naive version's silent leak.

What's still missing is rate limiting. An attacker could still bombard the forgot-password endpoint with requests, and while the generic response prevents enumeration, it does nothing to prevent email-bombing attacks or load amplification against the mail server.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| No rate limiting on the forgot-password endpoint | High | Manual review |
| Reset link printed to stdout in dev helper function | Medium | Manual review |

## What ChatGPT Got Right

Storing hashed tokens instead of raw tokens is the kind of detail that's easy to miss and matters a lot when it happens. The atomic single-use enforcement through the `UPDATE ... WHERE used_at IS NULL` pattern is a textbook solution to a real concurrency problem. The new tokens table cleans up old unused tokens for the same user when a new request comes in, which limits the attack surface. Password validation is comprehensive. The hashing algorithm is explicitly specified. The generic response message prevents enumeration. Tokens expire after thirty minutes. The reset confirmation flash message doesn't reveal whether anything actually happened. And the `SECRET_KEY` pulls from the environment with a secure fallback.

## What I'd Fix

Add rate limiting to the forgot-password endpoint, something like three requests per hour per IP and per email. Replace the `print()` call with a real email integration, even if it's still a stub for testing — the comment about not logging tokens is good but the code still does exactly that in development.