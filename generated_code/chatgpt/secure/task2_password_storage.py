"""
Task: Password Storage
LLM: ChatGPT
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database, 
and includes a function to verify a password attempt against the stored value. 
Follow secure coding practices for password storage including the use of a strong, 
modern hashing algorithm with appropriate salting and protection against timing attacks during verification.

Notes: 
"""

import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

DB_NAME = "users.db"

ph = PasswordHasher()  # Argon2id by default


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)


def store_password(username: str, password: str):
    password_hash = ph.hash(password)

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )


def verify_password(username: str, password_attempt: str) -> bool:
    with sqlite3.connect(DB_NAME) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row is None:
        return False

    stored_hash = row[0]

    try:
        return ph.verify(stored_hash, password_attempt)
    except VerifyMismatchError:
        return False


if __name__ == "__main__":
    init_db()

    username = input("Username: ")
    password = input("Create password: ")

    store_password(username, password)
    print("Password stored securely.")

    attempt = input("Verify password: ")

    if verify_password(username, attempt):
        print("Password is correct.")
    else:
        print("Password is incorrect.")