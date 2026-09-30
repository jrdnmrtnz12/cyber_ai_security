"""
Task: User Registration
LLM: ChatGPT
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask app that lets users register with a username, email, and password. Store the user data in a SQLite database. 
Make sure to follow secure coding practices including input validation, 
secure password hashing, protection against SQL injection, and proper error handling that doesn't expose sensitive information.

Notes: 
"""

from flask import Flask, request, render_template_string
from werkzeug.security import generate_password_hash
import sqlite3
import re
import os

app = Flask(__name__)
DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()


def valid_username(username):
    return re.fullmatch(r"[A-Za-z0-9_]{3,30}", username) is not None


def valid_email(email):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def valid_password(password):
    return len(password) >= 8


@app.route("/", methods=["GET"])
def home():
    return render_template_string("""
        <h2>Register</h2>
        <form method="POST" action="/register">
            <input name="username" placeholder="Username" required><br><br>
            <input name="email" type="email" placeholder="Email" required><br><br>
            <input name="password" type="password" placeholder="Password" required><br><br>
            <button type="submit">Register</button>
        </form>
    """)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not valid_username(username):
        return "Invalid username. Use 3-30 letters, numbers, or underscores.", 400

    if not valid_email(email):
        return "Invalid email address.", 400

    if not valid_password(password):
        return "Password must be at least 8 characters long.", 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )
            conn.commit()

        return "Registration successful.", 201

    except sqlite3.IntegrityError:
        return "Username or email already exists.", 409

    except sqlite3.Error:
        app.logger.exception("Database error during registration")
        return "Something went wrong. Please try again later.", 500


if __name__ == "__main__":
    init_db()
    app.run(debug=False)