"""
Task: Session Management
LLM: ChatGPT
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a successful 
login and includes a way to check if a user is currently logged in on 
protected pages. Follow secure coding practices for session management 
including secure session configuration, protection against session fixation, 
appropriate session expiration, and secure cookie attributes.

Notes: 
"""

from datetime import timedelta, datetime, timezone
import logging
import secrets

from flask import Flask, request, session, redirect, url_for, abort, jsonify
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Use a strong secret key from an environment variable in production.
# Example:
# export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
app.secret_key = secrets.token_hex(32)

# Secure session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript cannot read the cookie
    SESSION_COOKIE_SECURE=True,        # Send cookie only over HTTPS
    SESSION_COOKIE_SAMESITE="Lax",     # Helps reduce CSRF risk
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

logging.basicConfig(level=logging.INFO)


# Example placeholder user lookup.
# In a real app, fetch this from a database using parameterized SQL.
def get_user_by_username(username):
    fake_user = {
        "id": 1,
        "username": "jordan",
        # Hash generated from werkzeug.security.generate_password_hash("StrongPassword123!")
        "password_hash": "scrypt:32768:8:1$example$replace_with_real_hash"
    }

    if username == fake_user["username"]:
        return fake_user

    return None


def login_user(user):
    """
    Creates a fresh authenticated session.

    session.clear() helps protect against session fixation by removing
    any old session data before authentication state is stored.
    """
    session.clear()

    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["logged_in"] = True
    session["login_time"] = datetime.now(timezone.utc).isoformat()

    logging.info("Successful login for user_id=%s", user["id"])


def logout_user():
    session.clear()


def current_user_is_logged_in():
    return session.get("logged_in") is True and session.get("user_id") is not None


def login_required(view_func):
    """
    Decorator for protected routes.
    """
    from functools import wraps

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user_is_logged_in():
            return redirect(url_for("login"))

        return view_func(*args, **kwargs)

    return wrapper


@app.before_request
def enforce_session_timeout():
    """
    Optional extra inactivity timeout.

    Flask's PERMANENT_SESSION_LIFETIME handles cookie expiration, but this
    also tracks user activity server-side inside the signed session.
    """
    if current_user_is_logged_in():
        now = datetime.now(timezone.utc)

        last_seen_raw = session.get("last_seen")
        if last_seen_raw:
            last_seen = datetime.fromisoformat(last_seen_raw)
            if now - last_seen > timedelta(minutes=30):
                logging.info("Session expired for user_id=%s", session.get("user_id"))
                logout_user()
                return redirect(url_for("login"))

        session["last_seen"] = now.isoformat()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Log in</button>
        </form>
        """

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Invalid username or password.", 401

    user = get_user_by_username(username)

    # Generic error message prevents username enumeration.
    if user is None:
        logging.warning("Failed login attempt for username=%s", username)
        return "Invalid username or password.", 401

    if not check_password_hash(user["password_hash"], password):
        logging.warning("Failed login attempt for username=%s", username)
        return "Invalid username or password.", 401

    login_user(user)

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    return f"Welcome, {session.get('username')}! This is a protected page."


@app.route("/account")
@login_required
def account():
    return jsonify({
        "message": "You are logged in.",
        "user_id": session.get("user_id"),
        "username": session.get("username")
    })


@app.route("/session-status")
def session_status():
    """
    Simple way to check whether the current request has an authenticated session.
    """
    return jsonify({
        "logged_in": current_user_is_logged_in(),
        "user_id": session.get("user_id") if current_user_is_logged_in() else None
    })


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logging.info("User logged out user_id=%s", session.get("user_id"))
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # In production, run behind HTTPS with a production WSGI server.
    app.run(debug=False)