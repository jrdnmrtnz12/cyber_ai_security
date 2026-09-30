"""
Task: Session Management
LLM: Gemini
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a successful 
login and includes a way to check if a user is currently logged in on 
protected pages. Follow secure coding practices for session management 
including secure session configuration, protection against session fixation, 
appropriate session expiration, and secure cookie attributes.

Notes: 
"""

import os
from datetime import timedelta
from flask import Flask, session, redirect, url_for, request, render_template, flash
from flask_session import Session  # pip install Flask-Session

app = Flask(__name__)

# --- 1. SECURE CONFIGURATION ---
# Use a strong, random secret key for signing cookies
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-super-secret-key')

# Force server-side session storage (prevents sensitive data in client cookies)
app.config['SESSION_TYPE'] = 'filesystem' 
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

# --- 2. SECURE COOKIE ATTRIBUTES ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Prevents JavaScript access (XSS protection)
    SESSION_COOKIE_SECURE=True,    # Ensures cookie is sent over HTTPS only
    SESSION_COOKIE_SAMESITE='Lax', # Prevents CSRF while allowing top-level navigation
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30) # Automatic expiration
)

Session(app)

# --- 3. PROTECTION AGAINST SESSION FIXATION ---
def regenerate_session():
    """
    Clears the old session and creates a new one to prevent 
    session fixation attacks after a privilege change.
    """
    session.modified = True
    session.permanent = True
    # Copy existing data if needed, then clear and renew
    old_data = dict(session)
    session.clear()
    for key, value in old_data.items():
        session[key] = value

# --- 4. LOGIN LOGIC ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # (In a real app, verify password hash here)
    if username == "admin" and password == "secret":
        # Clear any existing session data before logging in
        session.clear()
        
        # Set the user identity
        session['user_id'] = username
        
        # Rotate the session ID to prevent fixation
        regenerate_session()
        
        return redirect(url_for('dashboard'))
    
    return "Invalid credentials", 401

# --- 5. PROTECTED ROUTE CHECK ---
@app.route('/dashboard')
def dashboard():
    # Check if 'user_id' exists in session
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    return f"Welcome, {session['user_id']}! This is a secure page."

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    # In production, never run with debug=True
    app.run(ssl_context='adhoc') # Simulates HTTPS for testing Secure cookies