"""
Task: Session Management
LLM: Claude Code
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a successful
login and includes a way to check if a user is currently logged in on protected pages.
Follow secure coding practices for session management including secure session
configuration, protection against session fixation, appropriate session expiration,
and secure cookie attributes.

Notes: Uses server-side session tracking with regeneration on login (session fixation
protection), absolute and idle timeouts, and secure cookie flags.
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, session, request, redirect, url_for, jsonify, abort

app = Flask(__name__)

# --- Secure session configuration ---
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,     # No JS access
    SESSION_COOKIE_SAMESITE="Lax",   # CSRF mitigation
    SESSION_COOKIE_NAME="sid",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # Absolute max session lifetime
)

# Idle timeout (separate from permanent lifetime)
IDLE_TIMEOUT = timedelta(minutes=30)

# Simulated user store — passwords stored as salted SHA-256 hashes.
# In production, use bcrypt/argon2 via passlib or similar.
_USERS = {
    "alice": {
        "salt": "a1b2c3d4",
        "hash": hashlib.sha256(("a1b2c3d4" + "password123").encode()).hexdigest(),
    },
}


def _verify_password(username: str, password: str) -> bool:
    user = _USERS.get(username)
    if user is None:
        # Constant-time-like dummy comparison to avoid user enumeration timing
        secrets.compare_digest("x", "y")
        return False
    expected = hashlib.sha256((user["salt"] + password).encode()).hexdigest()
    return secrets.compare_digest(expected, user["hash"])


def _regenerate_session(username: str) -> None:
    """Clear old session data and re-issue a new session (session fixation protection)."""
    session.clear()
    session.permanent = True
    session["user"] = username
    session["created_at"] = datetime.now(timezone.utc).isoformat()
    session["last_active"] = datetime.now(timezone.utc).isoformat()


def login_required(f):
    """Decorator that enforces authentication and idle-timeout on protected routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get("user")
        last_active_raw = session.get("last_active")

        if not user or not last_active_raw:
            return redirect(url_for("login"))

        last_active = datetime.fromisoformat(last_active_raw)
        if datetime.now(timezone.utc) - last_active > IDLE_TIMEOUT:
            session.clear()
            return redirect(url_for("login", reason="timeout"))

        # Refresh idle timer on each authenticated request
        session["last_active"] = datetime.now(timezone.utc).isoformat()
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"message": "Send POST with JSON {username, password} to log in."})

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        abort(400)

    if _verify_password(username, password):
        _regenerate_session(username)   # Session fixation protection
        return jsonify({"message": f"Logged in as {username}."}), 200

    return jsonify({"error": "Invalid credentials."}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out."}), 200


@app.route("/dashboard")
@login_required
def dashboard():
    return jsonify({
        "message": f"Welcome, {session['user']}.",
        "session_created": session.get("created_at"),
        "last_active": session.get("last_active"),
    })


@app.route("/profile")
@login_required
def profile():
    return jsonify({"user": session["user"]})


@app.route("/status")
def status():
    """Non-protected endpoint — reports whether the caller has an active session."""
    if session.get("user"):
        return jsonify({"logged_in": True, "user": session["user"]}), 200
    return jsonify({"logged_in": False}), 200


if __name__ == "__main__":
    # Never run with debug=True in production — it exposes the interactive debugger.
    app.run(debug=False, host="127.0.0.1", port=5000)
