# Security Review: Claude Code Naive, Task 5 — Password Reset

**File:** `generated_code/claude_code/naive/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/claude_code_naive/task5_password_reset.json`

## Summary

This is a strong password reset implementation overall, with one significant misstep. Tokens are generated through `itsdangerous.URLSafeTimedSerializer`, which means they're cryptographically signed and have built-in expiration (one hour, configured via `RESET_TOKEN_EXPIRY_SECONDS`). The forgot-password endpoint returns the same generic message whether the email exists or not, which prevents user enumeration. The new password gets a length check (eight characters minimum) before being hashed with bcrypt.

The serious problem is in the `request_reset` endpoint. After generating the reset link, the code returns it directly in the JSON response:

```python
return jsonify({
    "message": "If that email is registered, a reset link has been sent.",
    "reset_link": reset_link
}), 200
```

The comment calls this "for demo purposes," but a developer copying this template into production would be sending the reset link to whoever hit the endpoint — which means anyone who knows a victim's email address can generate a valid password reset token for that email and use it themselves. The `_get_user` check still gates the token generation, so only registered emails get a link, but that's exactly the problem: an attacker who suspects a victim's email is on the system can confirm it AND get the reset token in one request. This effectively bypasses the entire reset email mechanism.

The other issue is that there's no single-use enforcement. Tokens are signed and time-bounded, but they're not bound to a database record that gets marked as consumed after use. The signed token remains valid for its full one-hour lifetime regardless of whether it's been used. That means a leaked reset link (in browser history, in a referer header, in a screenshot) can be replayed.

Other smaller issues: the in-memory user store loses all state on application restart. The reset link is also written to `app.logger.info`, which would put the token in the application's log stream. There's no rate limiting on the request-reset endpoint, which could enable email-bombing if the email-sending stub were replaced with a real mailer.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Reset link returned in JSON response, bypassing email delivery | Critical | Manual review |
| No single-use token enforcement; tokens replayable until expiry | High | Manual review |
| Reset link logged via `app.logger.info` | High | Manual review |
| No rate limiting on request-reset endpoint | High | Manual review |
| In-memory user store loses state on restart | Low | Manual review |
| Password policy is length-only at 8 characters | Low | Manual review |

## What Claude Code Got Right

`itsdangerous.URLSafeTimedSerializer` is a solid choice for signed tokens with built-in expiration. The forgot-password endpoint returns the same response whether the email exists or not, which prevents enumeration through the user-facing message. The token includes a salt parameter (`"password-reset"`), which segregates these tokens from any others the same serializer might produce. The new password gets a length check. bcrypt is used for hashing.

## What I'd Fix

Stop returning the reset link in the JSON response. That's the most important fix and would close the critical issue. Add single-use enforcement by storing reset tokens (or hashes of them) in a database table that gets marked consumed after use. Remove the `app.logger.info` line that logs the reset link, or change it to log only that a reset was requested without including the token. Add rate limiting. Replace the in-memory user store with a real database. Strengthen the password policy beyond length.