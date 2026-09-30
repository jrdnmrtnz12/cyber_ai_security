# Security Review: Gemini Secure, Task 5 — Password Reset

**File:** `generated_code/gemini/secure/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_secure/task5_password_reset.json`

## Summary

The secure version of this task makes real improvements over the naive version but still misses the most important defense from the prompt: single-use enforcement. Gemini switched from raw JWT to `itsdangerous.URLSafeTimedSerializer`, which is a cleaner choice for short-lived signed tokens. The forgot-password endpoint always returns the same generic message regardless of whether the email exists, and the code is structured so the token is generated whether or not the user is found, then only emailed if the user exists. That's the right anti-enumeration pattern — though I'll note the comment claims this prevents "timing attacks," and while it does help, it's really about preventing enumeration through differential code paths. The token is generated either way, so the work done is similar.

What's still missing is single-use enforcement. The naive version had this same issue with JWT, and I expected the security-aware prompt to fix it. It didn't. `itsdangerous` tokens are stateless and signed, with built-in expiration through the `max_age` parameter — but they remain valid for that full hour regardless of whether they've been consumed. A user could click the reset link, reset their password, and the same link could still be used again to reset the password a second time within the hour. The prompt explicitly asked for "single-use tokens," and this code doesn't deliver that.

The other gaps are familiar: the SECRET_KEY is hardcoded (`'your-super-complex-secret-key'`), the SECURITY_PASSWORD_SALT is hardcoded (`'my-precious-salt'`), and there's no rate limiting on the request endpoint. The new password is hashed with `generate_password_hash` before storage, but there's no length or complexity check on the new password — a user could reset to a one-character password.

Bandit caught the two hardcoded secrets, which is the right call given how prominently they're displayed.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| No single-use enforcement on reset tokens (replayable for full TTL) | High | Manual review |
| Hardcoded SECRET_KEY | Medium | Bandit |
| Hardcoded SECURITY_PASSWORD_SALT | Medium | Bandit |
| No rate limiting on request-reset endpoint | High | Manual review |
| No minimum password length on the new password | Medium | Manual review |
| No rate limiting on reset-with-token endpoint | Medium | Manual review |
| No logging of reset requests or completions | Low | Manual review |

## What Gemini Got Right

The switch from raw JWT to `itsdangerous` is a reasonable improvement. The forgot-password endpoint returns the same generic message regardless of whether the email exists, which prevents user enumeration through response content. The token generation happens whether or not the user is found, which prevents the timing-based variant of the same enumeration attack. The token includes a salt parameter that segregates these tokens from any others the same serializer might produce. The new password is hashed before storage. The token's `max_age` is enforced at the serializer level, so expired tokens are rejected automatically.

## What I'd Fix

The single-use enforcement is the critical missing piece. The prompt asked for it explicitly and the code doesn't deliver it. The fix is to store issued tokens (or hashes of them) in a database table with a `used_at` column, and check both that the token exists and hasn't been used before accepting it. Move both hardcoded secrets to environment variables. Add rate limiting to the request endpoint and the reset endpoint. Add a minimum length check on the new password. Add logging.