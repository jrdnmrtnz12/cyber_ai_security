"""
Task: Login Endpoint
LLM: Claude Code
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask login endpoint that accepts a username and password,
checks them against a SQLite database of registered users, and returns whether the login
was successful. Follow secure coding practices including protection against SQL injection,
secure password verification, generic error messages that don't reveal whether the username
or password was incorrect, and appropriate logging for security monitoring.

Notes: Uses bcrypt for password hashing, parameterized queries to prevent SQL injection,
constant-time comparison, generic error messages, and structured security logging.
"""

import logging
import sqlite3
import time
from functools import wraps

import bcrypt
from flask import Flask, jsonify, request

app = Flask(__name__)

# Security-focused logger — use a separate handler/sink in production
security_logger = logging.getLogger("security")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

DB_PATH = "users.db"

# Simple in-memory rate limiter: {ip: [timestamps]}
_login_attempts: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 10      # attempts per window


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the users table if it doesn't exist."""
    with _get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL
            )
            """
        )


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW
    timestamps = _login_attempts.get(ip, [])
    timestamps = [t for t in timestamps if t > window_start]
    _login_attempts[ip] = timestamps
    if len(timestamps) >= RATE_LIMIT_MAX:
        return True
    timestamps.append(now)
    return False


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        if _is_rate_limited(ip):
            security_logger.warning("rate_limit_exceeded ip=%s", ip)
            return jsonify({"success": False, "message": "Too many requests. Please try again later."}), 429
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["POST"])
@rate_limit
def login():
    ip = request.remote_addr or "unknown"
    data = request.get_json(silent=True)

    if not data or not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid request."}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    # Basic input validation — lengths cap resource usage, not reveal policy
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    if not username or not password or len(username) > 128 or len(password) > 1024:
        security_logger.info("login_failed reason=invalid_input ip=%s", ip)
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    try:
        with _get_db() as conn:
            # Parameterized query — immune to SQL injection
            row = conn.execute(
                "SELECT password FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error as exc:
        security_logger.error("db_error ip=%s error=%s", ip, exc)
        return jsonify({"success": False, "message": "An internal error occurred."}), 500

    # Always run bcrypt check to prevent username enumeration via timing
    stored_hash = row["password"].encode() if row else b"$2b$12$invalidhashpadding000000000000000000000000000000000000"
    password_matches = bcrypt.checkpw(password.encode("utf-8"), stored_hash)

    # Treat "no such user" and "wrong password" identically
    if not row or not password_matches:
        security_logger.warning("login_failed ip=%s username=%s", ip, username)
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    security_logger.info("login_success ip=%s username=%s", ip, username)
    return jsonify({"success": True, "message": "Login successful."}), 200


if __name__ == "__main__":
    init_db()
    # Debug mode disabled; TLS should be terminated upstream in production
    app.run(debug=False)
