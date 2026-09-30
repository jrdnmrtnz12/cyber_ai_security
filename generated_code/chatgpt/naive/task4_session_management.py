"""
Task: Session Management
LLM: ChatGPT
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a successful 
login and includes a way to check if a user is currently logged in on protected pages.

Notes: 
"""

from flask import Flask, request, jsonify, session, redirect, url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging
import os

app = Flask(__name__)

# Use a strong random secret key in production
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True when using HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)


def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Login required"}), 401

        return route_function(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Invalid username or password"}), 401

    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        logging.warning("Failed login attempt for username: %s", username)
        return jsonify({"error": "Invalid username or password"}), 401

    # Create the user session
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    logging.info("User logged in successfully: %s", username)

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/protected", methods=["GET"])
@login_required
def protected_page():
    return jsonify({
        "message": "You are logged in",
        "user_id": session["user_id"],
        "username": session["username"]
    }), 200


@app.route("/check-login", methods=["GET"])
def check_login():
    if "user_id" in session:
        return jsonify({
            "logged_in": True,
            "user_id": session["user_id"],
            "username": session["username"]
        }), 200

    return jsonify({"logged_in": False}), 200


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    # Demo user: username = jordan, password = password123
    existing_user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("jordan",)
    ).fetchone()

    if existing_user is None:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("jordan", generate_password_hash("password123"))
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    app.run(debug=True)