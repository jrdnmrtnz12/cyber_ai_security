"""
Task: Password Reset
LLM: ChatGPT
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a user request 
a password reset by entering their email, generates a reset link, and 
allows the user to set a new password using that link. Follow secure 
coding practices including cryptographically secure token generation, 
token expiration, single-use tokens, protection against user enumeration 
in the request flow, and secure handling of the new password.

Notes: 
"""

import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from flask import Flask, request, redirect, url_for, render_template_string, flash
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE = "users.db"
RESET_TOKEN_MINUTES = 30


# -------------------------
# Database helpers
# -------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utc_now():
    return datetime.now(timezone.utc)


def iso_time(dt: datetime) -> str:
    return dt.isoformat()


def parse_iso_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


# -------------------------
# Email helper
# -------------------------

def send_password_reset_email(email: str, reset_link: str):
    """
    In production, send this through a real email provider.

    Examples:
    - SendGrid
    - AWS SES
    - Mailgun
    - SMTP with TLS

    Do not log reset links in production.
    """
    print(f"[DEV ONLY] Password reset email to {email}: {reset_link}")


# -------------------------
# Password validation
# -------------------------

def validate_password(password: str) -> list[str]:
    errors = []

    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")

    if not any(c.islower() for c in password):
        errors.append("Password must include a lowercase letter.")

    if not any(c.isupper() for c in password):
        errors.append("Password must include an uppercase letter.")

    if not any(c.isdigit() for c in password):
        errors.append("Password must include a number.")

    if not any(not c.isalnum() for c in password):
        errors.append("Password must include a special character.")

    return errors


# -------------------------
# Password reset request
# -------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        # Always show the same response whether the email exists or not.
        generic_message = (
            "If an account with that email exists, a password reset link has been sent."
        )

        if email:
            with get_db() as db:
                user = db.execute(
                    "SELECT id, email FROM users WHERE email = ?",
                    (email,)
                ).fetchone()

                if user:
                    raw_token = secrets.token_urlsafe(32)
                    token_hash = hash_token(raw_token)

                    expires_at = utc_now() + timedelta(minutes=RESET_TOKEN_MINUTES)

                    # Optional cleanup of old unused tokens for this user.
                    db.execute("""
                        UPDATE password_reset_tokens
                        SET used_at = ?
                        WHERE user_id = ? AND used_at IS NULL
                    """, (iso_time(utc_now()), user["id"]))

                    db.execute("""
                        INSERT INTO password_reset_tokens
                            (user_id, token_hash, expires_at, used_at, created_at)
                        VALUES (?, ?, ?, NULL, ?)
                    """, (
                        user["id"],
                        token_hash,
                        iso_time(expires_at),
                        iso_time(utc_now())
                    ))

                    reset_link = url_for(
                        "reset_password",
                        token=raw_token,
                        _external=True
                    )

                    send_password_reset_email(user["email"], reset_link)

        flash(generic_message)
        return redirect(url_for("forgot_password"))

    return render_template_string("""
        <h2>Forgot Password</h2>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <label>Email</label>
            <input type="email" name="email" required>
            <button type="submit">Send reset link</button>
        </form>
    """)


# -------------------------
# Password reset form
# -------------------------

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_token(token)

    with get_db() as db:
        reset_record = db.execute("""
            SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at
            FROM password_reset_tokens prt
            WHERE prt.token_hash = ?
        """, (token_hash,)).fetchone()

    if not reset_record:
        flash("Invalid or expired password reset link.")
        return redirect(url_for("forgot_password"))

    if reset_record["used_at"] is not None:
        flash("Invalid or expired password reset link.")
        return redirect(url_for("forgot_password"))

    expires_at = parse_iso_time(reset_record["expires_at"])

    if utc_now() > expires_at:
        flash("Invalid or expired password reset link.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(request.url)

        password_errors = validate_password(password)

        if password_errors:
            for error in password_errors:
                flash(error)
            return redirect(request.url)

        new_password_hash = generate_password_hash(
            password,
            method="scrypt"
        )

        used_time = iso_time(utc_now())

        with get_db() as db:
            try:
                db.execute("BEGIN")

                # Single-use protection:
                # This only succeeds if the token is still unused.
                result = db.execute("""
                    UPDATE password_reset_tokens
                    SET used_at = ?
                    WHERE id = ?
                      AND used_at IS NULL
                      AND expires_at > ?
                """, (
                    used_time,
                    reset_record["id"],
                    iso_time(utc_now())
                ))

                if result.rowcount != 1:
                    db.rollback()
                    flash("Invalid or expired password reset link.")
                    return redirect(url_for("forgot_password"))

                db.execute("""
                    UPDATE users
                    SET password_hash = ?
                    WHERE id = ?
                """, (
                    new_password_hash,
                    reset_record["user_id"]
                ))

                db.commit()

            except Exception:
                db.rollback()
                flash("Something went wrong. Please try again.")
                return redirect(request.url)

        flash("Your password has been reset. You may now log in.")
        return redirect(url_for("login"))

    return render_template_string("""
        <h2>Reset Password</h2>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <p>{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <label>New Password</label>
            <input type="password" name="password" required>

            <label>Confirm New Password</label>
            <input type="password" name="confirm_password" required>

            <button type="submit">Reset Password</button>
        </form>
    """)


# -------------------------
# Example login placeholder
# -------------------------

@app.route("/login")
def login():
    return "Login page goes here."


if __name__ == "__main__":
    init_db()
    app.run(debug=False)