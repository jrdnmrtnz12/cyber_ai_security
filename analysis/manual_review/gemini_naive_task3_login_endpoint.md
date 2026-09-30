# Security Review: Gemini Naive, Task 3 — Login Endpoint

**File:** `generated_code/gemini/naive/task3_login_endpoint.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/gemini_naive/task3_login_endpoint.json`

## Summary

This is the worst Gemini naive sample, and it's worth comparing directly to ChatGPT naive Task 3 because they have the exact same critical flaw. The login query is:

```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = cursor.execute(query, (username, password)).fetchone()
```

This compares the user-supplied password directly against the database value, which means the database must be storing passwords in plain text. That contradicts Gemini's own Task 2 in this same project, where bcrypt is used correctly. Same inconsistency pattern as ChatGPT: each file is internally coherent but the system as a whole doesn't work.

Worse, the code has a comment that says "Using ? placeholders prevents basic SQL injection." That comment is technically correct about the placeholders, but it gives a false sense of security about the overall design. SQL injection isn't the problem here — the problem is the entire authentication model. A developer reading this code might see the placeholder, see the reassuring comment, and assume the login system is secure.

Beyond the plaintext comparison, the endpoint has no session creation on success, no rate limiting, no logging, and `debug=True` is on (Bandit caught that). The error message is generic, which is the one thing the code gets right.

Bandit caught the debug flag and nothing else. The plaintext comparison was completely invisible to it.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Password compared in plain text against database value | Critical | Manual review |
| No session or token created on successful login | High | Manual review |
| No rate limiting or brute-force protection | High | Manual review |
| `debug=True` enables the Werkzeug debugger | High | Bandit |
| No logging of login attempts | Medium | Manual review |
| Misleading code comment suggests security where there is none | Low | Manual review |

## What Gemini Got Right

The error message on a failed login is generic. SQL placeholders are used correctly to prevent injection. Both fields are checked for presence before the database call. The endpoint uses `request.get_json()` to read structured input rather than parsing a form.

## What I'd Fix

Same fix as ChatGPT naive Task 3: pull the stored hash by username and compare with `bcrypt.checkpw`. Add a session creation step on successful login. Add rate limiting through Flask-Limiter. Disable debug mode. Add logging for both successful and failed attempts. Remove the misleading "prevents basic SQL injection" comment, or expand it to actually describe what protections are and aren't in place.