"""
Task: Password Storage
LLM: Gemini
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database,
and includes a function to verify a password attempt against the stored value.

Notes: 
"""

import sqlite3
import bcrypt

def init_db():
    """Creates the SQLite database and the users table."""
    with sqlite3.connect('auth_system.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL
            )
        ''')
        conn.commit()

def register_user(username, password):
    """Hashes the password and stores it in the database."""
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    try:
        with sqlite3.connect('auth_system.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                (username, hashed)
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def verify_login(username, password_attempt):
    """Retrieves the stored hash and verifies the password attempt."""
    with sqlite3.connect('auth_system.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
    if result:
        stored_hash = result[0]
        # bcrypt.checkpw handles extracting the salt from the hash automatically
        return bcrypt.checkpw(password_attempt.encode('utf-8'), stored_hash)
    
    return False

# --- Quick Test ---
if __name__ == "__main__":
    init_db()
    
    user = "dev_admin"
    secret = "P@ssw0rd123!"

    if register_user(user, secret):
        print(f"User '{user}' registered successfully.")
    
    # Verification tests
    print(f"Login success: {verify_login(user, secret)}")          # True
    print(f"Login success (wrong pw): {verify_login(user, 'wrong')}") # False