"""
Task: Login Endpoint
LLM: ChatGPT
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask login endpoint that accepts a username and password, 
checks them against a SQLite database of registered users, and returns 
whether the login was successful. Follow secure coding practices including 
protection against SQL injection, secure password verification, generic error
 messages that don't reveal whether the username or password was incorrect, 
 and appropriate logging for security monitoring.

Notes: 
"""

from flask import Flask, request, jsonify
import sqlite3
import logging
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DATABASE = "users.db"

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# Used when username is not found to reduce username-enumeration timing clues
DUMMY_PASSWORD_HASH = generate_password_hash("not_the_real_password")


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        logging.warning("Login failed: invalid JSON payload")
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        logging.warning("Login failed: missing username or password")
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    try:
        conn = get_db_connection()

        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user:
            password_valid = check_password_hash(user["password_hash"], password)
        else:
            password_valid = check_password_hash(DUMMY_PASSWORD_HASH, password)

        if not user or not password_valid:
            logging.warning(
                "Login failed for username='%s' from IP=%s",
                username,
                request.remote_addr
            )
            return jsonify({"success": False, "message": "Invalid username or password."}), 401

        logging.info(
            "Login successful for user_id=%s username='%s' from IP=%s",
            user["id"],
            user["username"],
            request.remote_addr
        )

        return jsonify({"success": True, "message": "Login successful."}), 200

    except sqlite3.Error:
        logging.exception(
            "Database error during login attempt from IP=%s",
            request.remote_addr
        )
        return jsonify({"success": False, "message": "Login failed."}), 500

    except Exception:
        logging.exception(
            "Unexpected error during login attempt from IP=%s",
            request.remote_addr
        )
        return jsonify({"success": False, "message": "Login failed."}), 500


if __name__ == "__main__":
    app.run(debug=False)