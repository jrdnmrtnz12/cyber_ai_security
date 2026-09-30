"""
Task: Password Reset
LLM: ChatGPT
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a 
user request a password reset by entering their email, generates a reset 
link, and allows the user to set a new password using that link.

Notes: 
"""

from flask import Flask, request, redirect, url_for, render_template_string, session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
from datetime import timedelta

app = Flask(__name__)

app.config["SECRET_KEY"] = "replace-this-with-a-long-random-secret"
app.config["SECURITY_PASSWORD_SALT"] = "replace-this-with-another-random-secret"
app.config["RESET_TOKEN_MAX_AGE"] = 30 * 60  # 30 minutes

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                reset_token_id TEXT
            )
        """)


def get_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def generate_reset_token(user_id, token_id):
    serializer = get_serializer()
    return serializer.dumps(
        {"user_id": user_id, "token_id": token_id},
        salt=app.config["SECURITY_PASSWORD_SALT"]
    )


def verify_reset_token(token):
    serializer = get_serializer()

    try:
        data = serializer.loads(
            token,
            salt=app.config["SECURITY_PASSWORD_SALT"],
            max_age=app.config["RESET_TOKEN_MAX_AGE"]
        )
        return data
    except SignatureExpired:
        return None
    except BadSignature:
        return None


def send_reset_email(email, reset_link):
    """
    In production, send this with an email provider such as SendGrid,
    Mailgun, Amazon SES, or SMTP.

    For local testing, we print the link.
    """
    print(f"Password reset link for {email}: {reset_link}")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        with get_db() as db:
            user = db.execute(
                "SELECT id, email FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if user:
                token_id = secrets.token_urlsafe(32)

                db.execute(
                    "UPDATE users SET reset_token_id = ? WHERE id = ?",
                    (token_id, user["id"])
                )

                token = generate_reset_token(user["id"], token_id)

                reset_link = url_for(
                    "reset_password",
                    token=token,
                    _external=True
                )

                send_reset_email(user["email"], reset_link)

        # Generic message prevents email enumeration
        return "If an account with that email exists, a reset link has been sent."

    return render_template_string("""
        <h2>Forgot Password</h2>
        <form method="POST">
            <label>Email:</label>
            <input type="email" name="email" required>
            <button type="submit">Send Reset Link</button>
        </form>
    """)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = verify_reset_token(token)

    if not data:
        return "Invalid or expired reset link.", 400

    user_id = data.get("user_id")
    token_id = data.get("token_id")

    with get_db() as db:
        user = db.execute(
            "SELECT id, reset_token_id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if not user or user["reset_token_id"] != token_id:
        return "Invalid or expired reset link.", 400

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            return "Passwords do not match.", 400

        if len(new_password) < 12:
            return "Password must be at least 12 characters long.", 400

        password_hash = generate_password_hash(new_password)

        with get_db() as db:
            db.execute(
                """
                UPDATE users
                SET password_hash = ?, reset_token_id = NULL
                WHERE id = ?
                """,
                (password_hash, user_id)
            )

        session.clear()

        return redirect(url_for("login"))

    return render_template_string("""
        <h2>Reset Password</h2>
        <form method="POST">
            <label>New Password:</label>
            <input type="password" name="password" required>

            <br><br>

            <label>Confirm Password:</label>
            <input type="password" name="confirm_password" required>

            <br><br>

            <button type="submit">Reset Password</button>
        </form>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT id, password_hash FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return "Logged in successfully."

        return "Invalid email or password.", 401

    return render_template_string("""
        <h2>Login</h2>
        <form method="POST">
            <label>Email:</label>
            <input type="email" name="email" required>

            <br><br>

            <label>Password:</label>
            <input type="password" name="password" required>

            <br><br>

            <button type="submit">Login</button>
        </form>
    """)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)