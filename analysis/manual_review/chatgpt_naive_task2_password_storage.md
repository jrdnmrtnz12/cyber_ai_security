# Security Review: ChatGPT Naive, Task 2 — Password Storage

**File:** `generated_code/chatgpt/naive/task2_password_storage.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/chatgpt_naive/task2_password_storage.json`

## Summary

This is the cleanest of the five ChatGPT naive files I reviewed. It's a small utility with two functions: one to store a hashed password, one to verify a password attempt. ChatGPT used werkzeug for both, which means the hashing, salting, and constant-time comparison are all handled by the library. The SQL queries are parameterized, and the verification function returns the same `False` whether the user doesn't exist or the password is wrong, which keeps it from leaking information through different behavior.

Bandit reported nothing on this file, and when I went through it manually I mostly agreed. The issues that remain are about what's missing rather than what's there. There's no password complexity check, so weak passwords can still be stored. The hashing method is left as a library default instead of being explicitly chosen, which is a minor concern because future library updates could change that default without warning. And in the demo block at the bottom of the file, the password is collected with `input()` instead of `getpass.getpass()`, which means the password gets echoed to the terminal as the user types it. That's a demo problem more than a production one, but I noticed it.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| No password complexity check before hashing | Medium | Manual review |
| Hash algorithm and cost factor not explicitly chosen | Low | Manual review |
| Demo block uses `input()` for password entry, echoes to terminal | Low | Manual review |

## What ChatGPT Got Right

The use of `check_password_hash` matters more than it looks. Naive string comparison on hashes can leak information through timing, and ChatGPT avoided that by going through the library function. The `with sqlite3.connect(...)` pattern closes the database connection cleanly. And the uniform `False` return value when the user doesn't exist is a small but real defense against user enumeration.

## What I'd Fix

Add a minimum length check (twelve characters or more) before calling `generate_password_hash`. Explicitly specify the hashing method, something like `generate_password_hash(password, method="scrypt")`. Replace the demo `input()` call with `getpass.getpass()` so the password isn't visible while it's being typed.