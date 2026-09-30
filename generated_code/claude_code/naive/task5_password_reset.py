"""
Task: Password Reset
LLM: Claude Code
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a user request a password reset
             by entering their email, generates a reset link, and allows the user to set a new
             password using that link.

Notes: Uses itsdangerous for signed tokens, bcrypt for password hashing.
       In production, replace the in-memory store with a real database and configure
       a real mail server via MAIL_SERVER settings.
"""

import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, abort, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["RESET_TOKEN_EXPIRY_SECONDS"] = 3600  # 1 hour

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# --- In-memory user store (replace with a real DB in production) ---
_users: dict[str, dict] = {
    "alice@example.com": {
        "password_hash": bcrypt.hashpw(b"hunter2", bcrypt.gensalt()),
    }
}


def _get_user(email: str) -> dict | None:
    return _users.get(email.lower())


def _set_password(email: str, new_password: str) -> None:
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    _users[email.lower()]["password_hash"] = pw_hash


def _generate_reset_token(email: str) -> str:
    return serializer.dumps(email.lower(), salt="password-reset")


def _verify_reset_token(token: str) -> str | None:
    """Returns the email encoded in the token, or None if invalid/expired."""
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=app.config["RESET_TOKEN_EXPIRY_SECONDS"],
        )
        return email
    except (SignatureExpired, BadSignature):
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/password-reset/request")
def request_reset():
    """Step 1 — user submits their email to request a reset link."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "email is required"}), 400

    # Always return 200 to avoid leaking whether an account exists.
    if _get_user(email):
        token = _generate_reset_token(email)
        reset_link = f"https://example.com/password-reset/confirm?token={token}"
        # In production send this via email; we return it here for demo purposes.
        app.logger.info("Reset link for %s: %s", email, reset_link)
        return jsonify({"message": "If that email is registered, a reset link has been sent.", "reset_link": reset_link}), 200

    return jsonify({"message": "If that email is registered, a reset link has been sent."}), 200


@app.post("/password-reset/confirm")
def confirm_reset():
    """Step 2 — user submits the token and their new password."""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("new_password") or ""

    if not token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    email = _verify_reset_token(token)
    if email is None:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    if not _get_user(email):
        # Account was deleted between request and confirmation.
        return jsonify({"error": "Invalid or expired reset token"}), 400

    _set_password(email, new_password)
    return jsonify({"message": "Password updated successfully"}), 200


if __name__ == "__main__":
    app.run(debug=False)
