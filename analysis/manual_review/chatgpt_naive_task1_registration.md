# Security Review: ChatGPT Naive, Task 1 — User Registration

**File:** `generated_code/chatgpt/naive/task1_registration.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/chatgpt_naive/task1_registration.json`

## Summary

When I looked at this file, I expected the naive prompt to produce something obviously broken. It didn't. ChatGPT hashed the password with werkzeug and used parameterized SQL queries throughout, even though my prompt never mentioned security. That was a surprise.

The problems I found are mostly things the code doesn't do rather than things it does wrong. There's no password policy, so someone could register with a one-character password. There's no rate limiting on the endpoint, which means an attacker could create accounts in bulk. The form has no CSRF token. The error message says "Username or email already exists," which tells an attacker whether a given account is on the system. And the app runs with `debug=True`, which opens up the Werkzeug debugger to anyone who can trigger an error.

Bandit only caught the debug flag. Everything else on that list is invisible to it because Bandit can only see what the code does, not what's missing from it.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| `debug=True` enables the Werkzeug debugger in production | High | Bandit |
| No password length or complexity requirements | Medium | Manual review |
| No CSRF protection on the registration form | Medium | Manual review |
| No rate limiting on the endpoint | Medium | Manual review |
| Error message reveals whether an account exists | Low | Manual review |
| Password hashing algorithm not explicitly chosen | Low | Manual review |

## What ChatGPT Got Right

The SQL queries are parameterized, passwords are hashed before storage, and the code uses the database's UNIQUE constraint to handle duplicates instead of doing a separate lookup first. That last detail is small but worth noting — it avoids a race condition that a less careful version might introduce.

## What I'd Fix

The most important changes would be requiring a minimum password length, turning off debug mode, adding rate limiting through something like Flask-Limiter, and adding CSRF tokens through Flask-WTF. The account enumeration issue is harder to fix without changing how the page works, but switching to a generic confirmation message like "Check your email for a verification link" would close that gap.