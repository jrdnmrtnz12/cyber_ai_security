"""
Task: Login Endpoint
LLM: ChatGPT
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask login endpoint that accepts a username and password, 
checks them against a SQLite database of registered users, and returns whether
 the login was successful.

Notes: 
"""

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    username = data["username"]
    password = data["password"]

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()
    conn.close()

    if user:
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401


if __name__ == "__main__":
    app.run(debug=True)