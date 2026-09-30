# Security Review: Claude Code Secure, Task 5 — Password Reset

**File:** `generated_code/claude_code/secure/task5_password_reset.py`
**Reviewer:** Jordan Martinez
**Review Date:** 2026-05-11
**Bandit Report:** `analysis/bandit_reports/claude_code_secure/task5_password_reset.json`

## Summary

This file fixes the critical flaw from the naive version. The naive Task 5 returned the reset token in the JSON response, which effectively bypassed the entire email-based reset flow. The secure version sends the token through a stub `_send_reset_email` function and only returns the generic "if that email is in our system" message, regardless of whether the email exists. That's the correct pattern.

The other major improvements are around token storage and single-use enforcement. Tokens are now stored as SHA-256 hashes in the `reset_tokens` dictionary, with the raw token only existing in the email link. This means even if the in-memory store leaks, an attacker can't use the hashes to reset passwords. Single-use enforcement is now real: each token record has a `"used"` boolean that gets set to `True` immediately after the token is validated, and subsequent attempts with the same token are rejected. Token entropy comes from `secrets.token_urlsafe(32)` (256 bits, more than enough). Tokens expire after one hour. The minimum password length is now twelve characters, up from the naive version's eight.

Bandit reported nothing. The remaining gaps are mostly about defense-in-depth that the prompt didn't specifically ask for. There's no rate limiting on either the request-reset or reset-password endpoints. The reset link is still written to stdout via `print()` in the `_send_reset_email` stub, which would put the token in production logs if the stub were replaced naively. The password policy is still length-only without character variety requirements. The in-memory user and token stores lose state on restart, which is fine for a demo but not for anything real.

## Findings

| Finding | Severity | How I Found It |
|---|---|---|
| Reset link printed to stdout in `_send_reset_email` stub | High | Manual review |
| No rate limiting on request-reset endpoint | High | Manual review |
| No rate limiting on reset-password endpoint | Medium | Manual review |
| Password policy is length-only at 12 characters | Low | Manual review |
| In-memory stores lose state on restart | Low | Manual review |

## What Claude Code Got Right

The critical flaw from the naive version is fixed. Token storage uses SHA-256 hashes of the actual tokens, which means the stored values can't be reused if leaked. Single-use enforcement is implemented through the `"used"` boolean that gets flipped immediately on validation. Token entropy is strong (256 bits via `secrets.token_urlsafe`). Token expiration is enforced server-side. The generic response message prevents user enumeration. The new password gets a length check before hashing. Werkzeug's `generate_password_hash` is used for storage. Both endpoints use parameterized data handling throughout (no SQL in this file since it's in-memory, but the pattern would carry over).

## What I'd Fix

Replace the `print()` call in `_send_reset_email` with a real email integration, and remove any logging that includes the raw token. Add rate limiting to both endpoints — the request-reset endpoint especially, since it could be used to flood a mail server. Strengthen the password policy beyond length. The in-memory store should obviously become a real database for production, but that's a scope limitation rather than a security flaw per se.