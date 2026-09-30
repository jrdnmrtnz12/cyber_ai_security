"""
Task: User Registration
LLM: Claude Code
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask app that lets users register with a username,
             email, and password. Store the user data in a SQLite database. Make
             sure to follow secure coding practices including input validation,
             secure password hashing, protection against SQL injection, and
             proper error handling that doesn't expose sensitive information.

Notes: Uses parameterized queries to prevent SQL injection, bcrypt-based
       password hashing via werkzeug, strict input validation with regex, and
       generic error responses that do not leak internal state. The SQLite
       database is created on first run. Passwords are never stored or logged
       in plaintext.
"""

import re
import sqlite3
import logging
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "users.db"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT    NOT NULL UNIQUE,
                email     TEXT    NOT NULL UNIQUE,
                password  TEXT    NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def validate_registration(username: str, email: str, password: str) -> list[str]:
    errors = []

    if not USERNAME_RE.match(username):
        errors.append(
            "Username must be 3–32 characters and contain only letters, digits, or underscores."
        )

    if not EMAIL_RE.match(email):
        errors.append("Invalid email address.")

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters.")

    return errors


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    errors = validate_registration(username, email, password)
    if errors:
        return jsonify({"errors": errors}), 422

    password_hash = generate_password_hash(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        # Username or email already exists — return a generic message to avoid
        # leaking which field caused the conflict.
        return jsonify({"error": "An account with that username or email already exists."}), 409
    except sqlite3.Error:
        logger.exception("Database error during registration")
        return jsonify({"error": "Registration failed. Please try again later."}), 500

    logger.info("New user registered: %s", username)
    return jsonify({"message": "Registration successful."}), 201


if __name__ == "__main__":
    init_db()
    # debug=False and host restricted to localhost for safe local development.
    app.run(debug=False, host="127.0.0.1", port=5000)
