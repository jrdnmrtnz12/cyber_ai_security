"""
Task: Password Reset
LLM: Gemini
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask password reset feature that lets a user 
request a password reset by entering their email, generates a reset link, 
and allows the user to set a new password using that link.

Notes: 
"""

import jwt
import datetime
from flask import Flask, request, render_template, url_for, flash, redirect
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key' # Keep this safe!
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

mail = Mail(app)

# Mock Database
users = {"user@example.com": {"password": "hashed_old_password"}}

def generate_reset_token(email):
    """Generates a JWT token valid for 30 minutes."""
    payload = {
        'reset_password': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_reset_token(token):
    """Decodes the token and returns the email if valid."""
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return data['reset_password']
    except Exception:
        return None

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        if email in users:
            token = generate_reset_token(email)
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com',
                          recipients=[email])
            link = url_for('reset_token', token=token, _external=True)
            msg.body = f'To reset your password, visit the following link: {link}'
            mail.send(msg)
        
        flash('If that account exists, a reset link has been sent.', 'info')
        return redirect(url_for('reset_request'))
    return '''
        <form method="POST">
            <input type="email" name="email" placeholder="Enter your email" required>
            <button type="submit">Send Reset Link</button>
        </form>
    '''

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_pw = generate_password_hash(new_password)
        users[email]['password'] = hashed_pw  # Update DB
        flash('Your password has been updated!', 'success')
        return "Password updated successfully!"

    return '''
        <form method="POST">
            <input type="password" name="password" placeholder="New Password" required>
            <button type="submit">Reset Password</button>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)