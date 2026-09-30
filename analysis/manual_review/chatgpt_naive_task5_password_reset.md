# Security Review: ChatGPT Naive, Task 5 — Password Reset

**File:** `generated_code/chatgpt/naive/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/chatgpt_naive/task5_password_reset.json`

## Summary

This is the strongest sample in the entire ChatGPT naive set, which surprised me because password reset flows are notoriously hard to get right even in production code. ChatGPT used `itsdangerous.URLSafeTimedSerializer` for the token, paired it with a separate `secrets.token_urlsafe(32)` value stored in the database as a single-use marker, and made the forgot-password endpoint return the same generic message whether the email exists or not. Tokens expire after thirty minutes, get bound to a specific user ID inside the signed payload, and are invalidated right after a successful reset by setting the database column to NULL. Session cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Lax`.

The token design is the part that I'd expect most developers to get wrong on their own, and ChatGPT got it right without being asked. The problems that remain are operational. The placeholder secret keys (`replace-this-with-a-long-random-secret`) are obvious to anyone who finds the source code. The reset link is sent through a `send_reset_email` function that just calls `print()`, which means the actual reset token would end up in the application's log stream in any real deployment. There's no rate limiting on the forgot-password endpoint, so an attacker could trigger reset emails in bulk to harass users or flood the mail server. And the password policy is just a length check at twelve characters, with no requirement for character variety.

Bandit flagged the placeholder strings as hardcoded passwords and caught the debug flag, but it missed the print statement leaking the token, the missing rate limiting, and the weak password policy.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| `debug=True` enables the Werkzeug debugger | High | Bandit |
| Reset link printed to stdout via `print()` | High | Manual review |
| No rate limiting on the forgot-password endpoint | High | Manual review |
| Hardcoded placeholder secret keys | Medium | Bandit |
| Password policy is length-only, no character variety required | Low | Manual review |

## What ChatGPT Got Right

This is essentially a textbook password reset implementation. The forgot-password endpoint doesn't reveal whether an email is on the system, the token is cryptographically secure and signed, expiration is enforced server-side, and the token gets invalidated immediately after use through a database flag that's checked at verification time. The token is bound to a specific user inside the payload, so it can't be repurposed. Session cookies have all three security flags set. After a successful reset, `session.clear()` forces the user to log in fresh with their new password.

## What I'd Fix

Replace the placeholder secret keys with values loaded from environment variables, and have the app refuse to start if they're not set. Remove the `print()` call from `send_reset_email` and replace it with a real email integration — and never log the token itself. Add rate limiting to the forgot-password endpoint, something like three requests per hour per IP. Extend the password policy beyond length to also require a mix of character types.