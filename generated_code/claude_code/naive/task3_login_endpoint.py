"""
Task: Login Endpoint
LLM: Claude Code
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask login endpoint that accepts a username and password,
checks them against a SQLite database of registered users, and returns whether
the login was successful.

Notes: Uses parameterized queries to prevent SQL injection, bcrypt for password hashing.
"""

import sqlite3
import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table if it doesn't exist."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        # Use a dummy check to avoid timing-based username enumeration
        bcrypt.checkpw(password.encode(), bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    if bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return jsonify({"success": True, "message": "Login successful"}), 200

    return jsonify({"success": False, "message": "Invalid username or password"}), 401


@app.route("/register", methods=["POST"])
def register():
    """Helper endpoint to create test users."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
        return jsonify({"success": True, "message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Username already exists"}), 409


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
