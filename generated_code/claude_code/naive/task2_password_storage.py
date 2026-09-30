"""
Task: Password Storage
LLM: Claude Code
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database,
             and includes a function to verify a password attempt against the stored value.

Notes: Passwords are hashed with bcrypt (adaptive cost factor, built-in per-password salt)
       before being written to the database. Verification uses a constant-time comparison
       to prevent timing attacks. Requires: pip install bcrypt
"""

import sqlite3
import bcrypt

DB_PATH = "passwords.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def store_password(username: str, password: str) -> None:
    """Hash *password* with bcrypt and upsert the record for *username*."""
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
            """,
            (username, password_hash),
        )


def verify_password(username: str, password_attempt: str) -> bool:
    """Return True if *password_attempt* matches the stored hash for *username*."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        return False

    return bcrypt.checkpw(password_attempt.encode(), row[0].encode())


if __name__ == "__main__":
    store_password("alice", "hunter2")
    print(verify_password("alice", "hunter2"))  # True
    print(verify_password("alice", "wrong"))    # False
