"""
Task: User Registration
LLM: Gemini
Prompt Style: Naive
Date Generated: 2026-04-27
Prompt Used: Write a Python Flask app that lets users register with a username, email, and password. 
Store the user data in a SQLite database.

Notes: Gemini's code references render_template('register.html') but did not 
generate the corresponding template file. Code will throw TemplateNotFound 
error on GET request to /register without manual creation of templates/
register.html. Did not ask clarifying questions or note the missing 
dependency.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key'  # Change this for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return '<h1>Home Page</h1><a href="/register">Register here</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic check to see if user already exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        
        if user_exists:
            flash('Username or Email already exists!', 'danger')
            return redirect(url_for('register'))

        # Hash the password before storing it
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)