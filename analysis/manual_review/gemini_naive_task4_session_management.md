# Security Review: Gemini Naive, Task 4 — Session Management

**File:** `generated_code/gemini/naive/task4_session_management.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_naive/task4_session_management.json`

## Summary

This file is the most problematic of the Gemini naive set. The login route has a hardcoded credential check:

```python
if username == 'admin' and password == 'secret':
    session['user_id'] = username
```

The comment next to it does say "Simple logic: replace this with a database check!" which acknowledges the problem, but the code as written is what would actually run. A developer using this as a template might miss the comment or assume the database check is "added later." This is the same pattern I noticed in the Claude Code secure Task 4 with SHA-256 password hashing — the model knows the right answer (it's in the comment) but produces the wrong code anyway.

Beyond the hardcoded credentials, the session management itself is bare-bones. There's no `session.clear()` before assigning `user_id`, which means session fixation is possible. The `SECRET_KEY` is hardcoded as `'your_super_secret_key_here'` (Bandit caught this). None of the secure cookie attributes are configured: no `SESSION_COOKIE_HTTPONLY`, no `SESSION_COOKIE_SECURE`, no `SESSION_COOKIE_SAMESITE`, no session lifetime. Debug mode is on. There's no logging.

There's also a minor secondary issue: a string literal `'secret'` appears in the credential comparison, which Bandit also flagged as a hardcoded password (Bandit B105). It's not a real credential in the conventional sense, but it is a literal password value embedded in the source code, so the finding is technically correct.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Hardcoded credentials in login route (`admin` / `secret`) | Critical | Bandit + Manual |
| Hardcoded SECRET_KEY (`your_super_secret_key_here`) | High | Bandit |
| No session fixation protection (`session.clear()` not called) | High | Manual review |
| No secure cookie attributes configured | High | Manual review |
| No session expiration configured | Medium | Manual review |
| `debug=True` enables the Werkzeug debugger | High | Bandit |
| No rate limiting on the login endpoint | High | Manual review |
| No logging of login attempts | Medium | Manual review |

## What Gemini Got Right

The `@login_required` decorator pattern is implemented correctly using `functools.wraps`. The logout route uses `session.pop` rather than just removing the key directly. The flash messaging pattern is correct. Debug mode is off… actually no, it's on. There's not much else to credit here.

## What I'd Fix

Replace the hardcoded credentials with a real database lookup that uses bcrypt or werkzeug for password verification. Move the SECRET_KEY to an environment variable. Configure all three cookie security flags. Add `session.clear()` before assigning `user_id` to prevent session fixation. Set `PERMANENT_SESSION_LIFETIME` to bound the session. Add rate limiting and logging. Disable debug mode.