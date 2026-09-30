"""
Task: Password Reset
LLM: Claude Code
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a user request
a password reset by entering their email, generates a reset link, and allows the
user to set a new password using that link. Follow secure coding practices
including cryptographically secure token generation, token expiration, single-use
tokens, protection against user enumeration in the request flow, and secure
handling of the new password.

Notes:
- Tokens are generated with secrets.token_urlsafe(32) (256 bits of entropy)
- Tokens expire after 1 hour and are invalidated after first use (single-use)
- Password reset request always returns the same response regardless of whether
  the email exists (prevents user enumeration)
- Passwords are hashed with bcrypt (via werkzeug) before storage
- Minimum password length enforced at reset time
"""

import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

TOKEN_TTL_SECONDS = 3600  # 1 hour
MIN_PASSWORD_LENGTH = 12

# --- In-memory stores (replace with a real database in production) ---

# email -> {"password_hash": str}
users: dict[str, dict] = {
    "alice@example.com": {"password_hash": generate_password_hash("hunter2hunter2")},
}

# token_hash -> {"email": str, "expires_at": datetime, "used": bool}
reset_tokens: dict[str, dict] = {}


def _hash_token(token: str) -> str:
    """Store a SHA-256 hash of the token, not the token itself."""
    return hashlib.sha256(token.encode()).hexdigest()


def _send_reset_email(email: str, token: str) -> None:
    """Stub — replace with real email delivery (e.g. SendGrid, SES)."""
    reset_link = f"https://example.com/reset-password?token={token}"
    print(f"[EMAIL] To: {email}  Link: {reset_link}")


@app.post("/request-password-reset")
def request_password_reset():
    """
    Accept an email address and — if an account exists — send a reset link.
    Always returns the same response to prevent user enumeration.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if email in users:
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        reset_tokens[token_hash] = {
            "email": email,
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TTL_SECONDS),
            "used": False,
        }
        _send_reset_email(email, token)

    # Identical response whether the email exists or not
    return jsonify({
        "message": "If that email address is in our system, you will receive a reset link shortly."
    }), 200


@app.post("/reset-password")
def reset_password():
    """
    Validate the reset token and set a new password.
    Token is invalidated immediately after use (single-use).
    """
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("new_password") or ""

    if not token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 400

    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({
            "error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        }), 400

    token_hash = _hash_token(token)
    record = reset_tokens.get(token_hash)

    if (
        record is None
        or record["used"]
        or datetime.now(timezone.utc) > record["expires_at"]
    ):
        return jsonify({"error": "Invalid or expired reset token"}), 400

    # Invalidate the token immediately (single-use)
    record["used"] = True

    email = record["email"]
    if email not in users:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    users[email]["password_hash"] = generate_password_hash(new_password)

    return jsonify({"message": "Password updated successfully"}), 200


@app.post("/login")
def login():
    """Minimal login endpoint to verify the new password works."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = users.get(email)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful"}), 200


if __name__ == "__main__":
    # Debug mode off in production; use a proper WSGI server (gunicorn, uvicorn)
    app.run(debug=False)
