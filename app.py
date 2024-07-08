import os
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import string
import logging
from jinja2 import BaseLoader, TemplateNotFound
from functools import wraps

# Load environment variables from .env file
load_dotenv()

# Custom template loader
class StringTemplateLoader(BaseLoader):
    def __init__(self, templates):
        self.templates = templates

    def get_source(self, environment, template):
        if template in self.templates:
            source = self.templates[template]
            return source, None, lambda: False
        raise TemplateNotFound(template)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Set this to True for development, False for production
app.config['MAIL_SUPPRESS_SEND'] = os.getenv('MAIL_SUPPRESS_SEND', 'true').lower() in ['true', 'on', '1']

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Passwordless Auth{% endblock %}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .flash { padding: 10px; margin-bottom: 10px; border-radius: 5px; }
        .flash-info { background-color: #e7f3fe; border: 1px solid #b6d4fe; }
        .flash-success { background-color: #d1e7dd; border: 1px solid #badbcc; }
        .flash-error { background-color: #f8d7da; border: 1px solid #f5c2c7; }
        .code-input { width: 30px; text-align: center; margin-right: 5px; }
    </style>
    {% block extra_head %}{% endblock %}
</head>
<body>
    <div class="container">
        <h1>{% block header %}{% endblock %}</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash flash-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

home_template = """
{% extends "base_template" %}
{% block title %}Home{% endblock %}
{% block header %}Welcome{% endblock %}
{% block content %}
    <p>Welcome to the Passwordless Auth Demo!</p>
    <p>You are logged in as {{ current_user.email }}.</p>
    <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    <br>
    <a href="{{ url_for('logout') }}">Logout</a>
{% endblock %}
"""

login_template = """
{% extends "base_template" %}
{% block title %}Login{% endblock %}
{% block header %}Login{% endblock %}
{% block extra_head %}
<script>
    function handlePaste(e) {
        e.preventDefault();
        const paste = (e.clipboardData || window.clipboardData).getData('text');
        const digits = paste.replace(/\\D/g, '').slice(0, 6);  // Note the double backslash here
        const inputs = document.querySelectorAll('.code-input');
        digits.split('').forEach((digit, index) => {
            if (inputs[index]) {
                inputs[index].value = digit;
                if (index === 5) {
                    document.getElementById('verify-form').submit();
                }
            }
        });
    }

    function handleInput(e) {
        const input = e.target;
        if (input.value.length === 1) {
            const nextInput = input.nextElementSibling;
            if (nextInput && nextInput.tagName === 'INPUT') {
                nextInput.focus();
            }
            if (input.getAttribute('data-index') === '5') {
                document.getElementById('verify-form').submit();
            }
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        const codeInputs = document.querySelectorAll('.code-input');
        codeInputs.forEach(input => {
            input.addEventListener('paste', handlePaste);
            input.addEventListener('input', handleInput);
        });
    });
</script>
{% endblock %}
{% block content %}
    {% if email_sent %}
        <p>We've sent a 6-digit code to your email. Please enter it below:</p>
        <form id="verify-form" method="POST" action="{{ url_for('verify_code') }}">
            <input type="hidden" name="email" value="{{ email }}">
            {% for i in range(6) %}
            <input type="text" name="code{{ i }}" class="code-input" maxlength="1" required pattern="[0-9]" inputmode="numeric" data-index="{{ i }}">
            {% endfor %}
            <button type="submit">Verify Code</button>
        </form>
        <p>Didn't receive the code? <a href="{{ url_for('login') }}">Try again</a></p>
    {% else %}
        <form method="POST">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
            <button type="submit">Send Login Code</button>
        </form>
    {% endif %}
{% endblock %}
"""

dashboard_template = """
{% extends "base_template" %}
{% block title %}Dashboard{% endblock %}
{% block header %}Dashboard{% endblock %}
{% block content %}
    <p>Welcome to your dashboard, {{ current_user.email }}!</p>
    <a href="{{ url_for('logout') }}">Logout</a>
{% endblock %}
"""

# Set up the custom template loader
templates = {
    'base_template': base_template,
    'home_template': home_template,
    'login_template': login_template,
    'dashboard_template': dashboard_template,
}
app.jinja_loader = StringTemplateLoader(templates)

# Routes
@app.route('/')
@login_required
def home():
    return render_template('home_template')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            db.session.add(user)
            db.session.commit()
        
        # Generate 6-digit token
        digit_token = ''.join(random.choices(string.digits, k=6))
        new_token = Token(user_id=user.id, token=digit_token)
        db.session.add(new_token)
        db.session.commit()
        
        # Create email message
        msg = Message('Your Login Code',
                      recipients=[email])
        msg.body = f'Your 6-digit login code is: {digit_token}'
        
        # Send email (or log it if in development mode)
        if app.config['MAIL_SUPPRESS_SEND']:
            logger.info(f"Email to: {email}")
            logger.info(f"Subject: {msg.subject}")
            logger.info(f"Body: {msg.body}")
        else:
            mail.send(msg)
        
        flash('We\'ve sent a 6-digit code to your email. Please check and enter it below.', 'info')
        return render_template('login_template', email_sent=True, email=email)
    
    return render_template('login_template', email_sent=False)

@app.route('/verify-code', methods=['POST'])
def verify_code():
    email = request.form['email']
    entered_code = ''.join([request.form.get(f'code{i}', '') for i in range(6)])
    user = User.query.filter_by(email=email).first()
    if user:
        token = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).first()
        if token and token.token == entered_code:
            if datetime.utcnow() - token.created_at <= timedelta(minutes=10):
                login_user(user)
                db.session.delete(token)
                db.session.commit()
                flash('You have been logged in successfully.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('The code has expired. Please request a new one.', 'error')
        else:
            flash('Invalid code. Please try again.', 'error')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard_template')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=8080)