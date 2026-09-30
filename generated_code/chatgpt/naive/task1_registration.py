"""
Task: User Registration
LLM: ChatGPT
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask app that lets users register with a 
username, email, and password. Store the user data in a SQLite database.

Notes: ChatGPT applied some security practices unprompted (password 
hashing via werkzeug, parameterized SQL queries). No clarifying questions 
asked. Returned a single complete code block.
"""

from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash

app = Flask(__name__)

DB_NAME = "users.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>Welcome</h1>
    <a href="/register">Register</a>
    """


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            """, (username, email, password_hash))

            conn.commit()
            conn.close()

            return redirect(url_for("success"))

        except sqlite3.IntegrityError:
            return "Username or email already exists."

    return render_template_string("""
        <h1>Register</h1>

        <form method="POST">
            <label>Username:</label><br>
            <input type="text" name="username" required><br><br>

            <label>Email:</label><br>
            <input type="email" name="email" required><br><br>

            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>

            <button type="submit">Register</button>
        </form>
    """)


@app.route("/success")
def success():
    return "<h1>Registration successful!</h1>"


if __name__ == "__main__":
    init_db()
    app.run(debug=True)