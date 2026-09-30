"""
Task: Password Storage
LLM: Gemini
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python code that takes a user's password, stores it in a SQLite database, 
and includes a function to verify a password attempt against the stored value. 
Follow secure coding practices for password storage including the use of a strong, 
modern hashing algorithm with appropriate salting and protection against timing attacks during verification.

Notes: 
"""

import sqlite3
import bcrypt

def initialize_db():
    """Sets up the SQLite database and users table."""
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    ''')
    conn.commit()
    return conn

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt. 
    Bcrypt automatically generates a unique salt and includes it in the hash.
    """
    # Convert string to bytes
    password_bytes = password.encode('utf-8')
    # Generate salt and hash
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt())

def register_user(username, password):
    """Hashes the password and stores the user in the database."""
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()
    
    hashed_pw = hash_password(password)
    
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                       (username, hashed_pw))
        conn.commit()
        print(f"User '{username}' registered successfully.")
    except sqlite3.IntegrityError:
        print("Error: Username already exists.")
    finally:
        conn.close()

def verify_login(username, provided_password):
    """
    Retrieves the stored hash and verifies the password attempt.
    bcrypt.checkpw is designed to prevent timing attacks.
    """
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash = result[0]
        # Verify the provided password against the stored hash
        if bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash):
            return True
    
    return False

# --- Example Usage ---
if __name__ == "__main__":
    initialize_db()
    
    # 1. Registration
    user_input_name = "jane_doe"
    user_input_pw = "SuperSecret123!"
    register_user(user_input_name, user_input_pw)

    # 2. Verification
    attempt = "SuperSecret123!"
    if verify_login(user_input_name, attempt):
        print("Login successful!")
    else:
        print("Invalid username or password.")