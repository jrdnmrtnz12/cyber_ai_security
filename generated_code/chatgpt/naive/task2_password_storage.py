"""
Task: Password Storage
LLM: ChatGPT
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database,
and includes a function to verify a password attempt against the stored value.

Notes: 
"""

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "users.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

def store_user(username, password):
    password_hash = generate_password_hash(password)

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

def verify_password(username, password_attempt):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

    if row is None:
        return False

    stored_hash = row[0]
    return check_password_hash(stored_hash, password_attempt)


# Example usage
if __name__ == "__main__":
    init_db()

    username = input("Username: ")
    password = input("Password: ")

    store_user(username, password)

    attempt = input("Try password again: ")

    if verify_password(username, attempt):
        print("Password is correct.")
    else:
        print("Password is incorrect.")