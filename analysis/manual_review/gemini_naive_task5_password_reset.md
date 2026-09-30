# Security Review: Gemini Naive, Task 5 — Password Reset

**File:** `generated_code/gemini/naive/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_naive/task5_password_reset.json`

## Summary

This file has more security thinking than the other Gemini naive samples but still has serious problems. On the positive side, Gemini used JWT tokens with HS256 signing for the reset link, set a thirty-minute expiration in the token payload, and the forgot-password endpoint returns the same generic message whether the email is on the system or not. That's all the right pattern.

The problems are elsewhere. The hardcoded SECRET_KEY (`'your_super_secret_key'`) is back, the SMTP credentials are inlined (`'your-email@gmail.com'` and `'your-app-password'`), and the mock user database stores what's labeled as a "hashed_old_password" but is just the literal string `"hashed_old_password"` — it's not actually a hash of anything. Bandit caught all three of those.

The bigger conceptual problem is that there's no single-use enforcement on the reset tokens. JWTs are stateless by design — they're valid until they expire, regardless of whether they've been used. A leaked reset link (in browser history, in a referer header, in a screenshot) stays usable for the full thirty minutes. The naive Claude Code Task 5 had the same issue. The correct pattern is to either store tokens in a database with a `used_at` column (like ChatGPT's secure Task 5 does), or to bind the JWT to a server-side value that gets invalidated after use.

There's also no rate limiting on the request endpoint, no password length check on the new password, and no logging.

Bandit caught the placeholder strings (SECRET_KEY, the fake email password, and the fake "hashed_old_password" value) plus the debug flag. The rest was invisible to it.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Hardcoded SECRET_KEY (`your_super_secret_key`) | High | Bandit |
| Hardcoded SMTP credentials (placeholder) | Medium | Bandit |
| Mock "hashed" password is literal string, not a real hash | Low | Bandit |
| `debug=True` enables the Werkzeug debugger | High | Bandit |
| No single-use enforcement on reset tokens (JWT replayable for full TTL) | High | Manual review |
| No rate limiting on the request-reset endpoint | High | Manual review |
| No minimum password length on the new password | Medium | Manual review |
| No logging of reset requests or completions | Low | Manual review |

## What Gemini Got Right

The use of JWT with HS256 is acceptable for signed tokens with built-in expiration. The thirty-minute expiry is reasonable. The forgot-password endpoint returns the same generic message whether the account exists or not, which is the right anti-enumeration pattern. The invalid-token path redirects to the request page with a generic message rather than revealing why the token failed. The new password is hashed with `generate_password_hash` before being stored.

## What I'd Fix

Move all secrets (SECRET_KEY, SMTP credentials) to environment variables. Add single-use enforcement by tracking issued tokens in a database with a `used_at` column, and reject any token that's already been consumed. Replace the mock user database with real persistence. Add a minimum length check on the new password. Add rate limiting to the request endpoint. Add logging. Disable debug mode.