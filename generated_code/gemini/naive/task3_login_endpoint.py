"""
Task: Login Endpoint
LLM: Gemini
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

def get_db_connection():
    # Connects to your local SQLite file
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['POST'])
def login():
    # Get credentials from the JSON request body
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Query the database for the user
    # Note: Using ? placeholders prevents basic SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    user = cursor.execute(query, (username, password)).fetchone()
    
    conn.close()

    if user:
        return jsonify({"message": "Login successful", "status": "success"}), 200
    else:
        return jsonify({"message": "Invalid credentials", "status": "fail"}), 401

if __name__ == '__main__':
    app.run(debug=True)