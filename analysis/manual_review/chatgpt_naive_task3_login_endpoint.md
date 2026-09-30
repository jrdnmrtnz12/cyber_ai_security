# Security Review: ChatGPT Naive, Task 3 — Login Endpoint

**File:** `generated_code/chatgpt/naive/task3_login_endpoint.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/chatgpt_naive/task3_login_endpoint.json`

## Summary

This is the worst of the ChatGPT naive files, and it's worth explaining why. The login endpoint queries the database with `SELECT * FROM users WHERE username = ? AND password = ?`, which means it's checking the password as if it were stored in plain text. That directly contradicts what ChatGPT produced for Task 1 in the same project, where the password gets hashed with werkzeug before being inserted into the database. If a developer copied both files into the same app, the authentication system literally wouldn't work, because the hash stored at registration would never match the raw password being compared at login.

I think this finding matters beyond just this one file. It shows a real risk with prompt-by-prompt AI code generation: each response is internally consistent, but consistency across separate responses isn't guaranteed. Bandit caught none of this because the SQL query is technically well-formed. As far as static analysis is concerned, the code looks clean.

Beyond the plaintext comparison, the login endpoint never creates a session or token after a successful login, so even a fixed version of this code wouldn't actually log anyone in. There's no rate limiting, no lockout after failed attempts, and no logging. The one thing it does well is return a generic error message that doesn't distinguish between "user not found" and "wrong password."

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Password compared in plain text against database value | Critical | Manual review |
| No session or token created on successful login | High | Manual review |
| No rate limiting or brute-force protection | High | Manual review |
| `debug=True` enables the Werkzeug debugger | High | Bandit |
| No logging of login attempts | Medium | Manual review |

## What ChatGPT Got Right

The error message on a failed login is generic and uniform, which keeps an attacker from learning whether a given username exists. The SQL uses parameterized placeholders. The endpoint checks that both `username` and `password` are present in the JSON body before doing anything with them.

## What I'd Fix

The plaintext comparison has to go. The query should pull the stored hash by username, and then `check_password_hash(stored_hash, password)` should verify the attempt. A session needs to be established after a successful login, ideally with `session.clear()` first to prevent session fixation. Rate limiting should be added through Flask-Limiter at something like five attempts per minute per IP. Debug mode needs to be off outside development. Both successful and failed login attempts should be written to a structured log.