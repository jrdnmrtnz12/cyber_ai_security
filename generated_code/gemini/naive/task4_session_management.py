"""
Task: Session Management
LLM: Gemini
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write Python Flask code that creates a user session after a 
successful login and includes a way to check if a user is currently logged in on protected pages.

Notes: 
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

app = Flask(__name__)

# Required to sign the session cookies
app.secret_key = 'your_super_secret_key_here'

# --- Decorator to Protect Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return "Home Page - <a href='/dashboard'>Go to Dashboard</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Simple logic: replace this with a database check!
        if username == 'admin' and password == 'secret':
            session['user_id'] = username  # Create the session
            flash("Successfully logged in!")
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401

    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    # Only accessible if 'user_id' is in session
    return f"Welcome to your dashboard, {session['user_id']}! <br><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    flash("You have been logged out.")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)