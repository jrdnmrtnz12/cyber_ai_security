"""
Task: Password Storage
LLM: Claude Code
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database,
and includes a function to verify a password attempt against the stored value.
Follow secure coding practices for password storage including the use of a strong,
modern hashing algorithm with appropriate salting and protection against timing attacks during verification.

Notes: Uses bcrypt for password hashing (adaptive, salted, slow by design).
       hmac.compare_digest provides constant-time comparison to prevent timing attacks.
"""

import sqlite3
import hmac
import bcrypt


DB_PATH = "users.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)


def store_password(username: str, password: str) -> None:
    """Hash password with bcrypt (random salt embedded) and persist to DB."""
    if not username or not password:
        raise ValueError("Username and password must be non-empty.")

    # bcrypt.hashpw generates a cryptographically random salt internally and
    # embeds it in the hash output — no separate salt column needed.
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )


def verify_password(username: str, password_attempt: str) -> bool:
    """Return True iff password_attempt matches the stored hash for username.

    Uses hmac.compare_digest on the bcrypt output to ensure constant-time
    comparison and prevent timing-based username enumeration.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        # Run a dummy bcrypt check so response time doesn't reveal whether the
        # username exists (timing-safe username enumeration prevention).
        bcrypt.checkpw(password_attempt.encode(), bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False

    stored_hash = row[0].encode()
    candidate_hash = bcrypt.hashpw(password_attempt.encode(), stored_hash)

    # constant-time byte comparison
    return hmac.compare_digest(candidate_hash, stored_hash)


if __name__ == "__main__":
    init_db()

    store_password("alice", "correct-horse-battery-staple")
    print("Password stored.")

    print(verify_password("alice", "correct-horse-battery-staple"))  # True
    print(verify_password("alice", "wrongpassword"))                  # False
    print(verify_password("bob",   "correct-horse-battery-staple"))   # False
