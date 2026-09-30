"""
Task: Session Management
LLM: Claude Code
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a successful login
             and includes a way to check if a user is currently logged in on protected pages.

Notes: Uses Flask-Login for session management with a secret key for session signing.
"""

from flask import Flask, request, jsonify, session, redirect, url_for
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Simulated user database
USERS = {
    "alice": "password123",
    "bob": "securepass",
}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if username in USERS and USERS[username] == password:
        session["username"] = username
        return jsonify({"message": f"Logged in as {username}"}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.pop("username", None)
    return jsonify({"message": f"User '{username}' logged out"}), 200


@app.route("/status")
def status():
    if "username" in session:
        return jsonify({"logged_in": True, "username": session["username"]}), 200
    return jsonify({"logged_in": False}), 200


@app.route("/dashboard")
@login_required
def dashboard():
    return jsonify({"message": f"Welcome, {session['username']}! This is your dashboard."}), 200


@app.route("/profile")
@login_required
def profile():
    return jsonify({"username": session["username"], "message": "This is a protected profile page."}), 200


if __name__ == "__main__":
    app.run(debug=False)
