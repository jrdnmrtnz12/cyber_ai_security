"""
Task: Password Reset
LLM: Gemini
Prompt Style: Security-Aware
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a user request 
a password reset by entering their email, generates a reset link, and 
allows the user to set a new password using that link. Follow secure 
coding practices including cryptographically secure token generation, 
token expiration, single-use tokens, protection against user enumeration 
in the request flow, and secure handling of the new password.

Notes: 
"""

from flask import Flask, request, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-complex-secret-key' # Use an env var!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECURITY_PASSWORD_SALT'] = 'my-precious-salt'

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# --- Logic: Request Reset ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        # Protective measure: Generate token regardless of user existence 
        # to prevent timing attacks, but only email if user exists.
        token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
        
        if user:
            send_reset_email(user.email, token)
        
        # User Enumeration Protection: Always show the same message
        flash("If an account exists with that email, a reset link has been sent.")
        return redirect(url_for('reset_request'))
        
    return render_template('reset_request.html')

# --- Logic: Reset with Token ---
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        # Token expires in 1 hour (3600 seconds)
        email = serializer.loads(
            token, 
            salt=app.config['SECURITY_PASSWORD_SALT'], 
            max_age=3600
        )
    except (SignatureExpired, BadTimeSignature):
        flash("The reset link is invalid or has expired.")
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        new_password = request.form.get('password')
        
        # Secure handling: Hash the new password immediately
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash("Your password has been updated!")
        return redirect(url_for('login'))

    return render_template('reset_token.html')

def send_reset_email(email, token):
    # Integration with Mailgun, SendGrid, or Flask-Mail goes here
    reset_url = url_for('reset_with_token', token=token, _external=True)
    print(f"DEBUG: Send this link to {email}: {reset_url}")