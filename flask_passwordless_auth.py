# flask_passwordless_auth.py

from flask import current_app, Flask, request, render_template_string, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import string
import logging
from functools import wraps

class PasswordlessAuth:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.db = SQLAlchemy(app)
        self.login_manager = LoginManager(app)
        self.login_manager.login_view = 'passwordless.login'
        self.mail = Mail(app)
        self.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Register models
        class User(UserMixin, self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            email = self.db.Column(self.db.String(100), unique=True, nullable=False)
            is_active = self.db.Column(self.db.Boolean, default=True)
            created_at = self.db.Column(self.db.DateTime, default=datetime.utcnow)

        class Token(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            user_id = self.db.Column(self.db.Integer, self.db.ForeignKey('user.id'), nullable=False)
            token = self.db.Column(self.db.String(6), nullable=False)
            created_at = self.db.Column(self.db.DateTime, default=datetime.utcnow)

        self.User = User
        self.Token = Token

        @self.login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        # Register routes
        app.add_url_rule('/login', 'passwordless.login', self.login, methods=['GET', 'POST'])
        app.add_url_rule('/verify-code', 'passwordless.verify_code', self.verify_code, methods=['POST'])
        app.add_url_rule('/logout', 'passwordless.logout', self.logout)

    def login_required(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('passwordless.login', next=request.url))
            return f(*args, **kwargs)
        return decorated_function

    def login(self):
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            email = request.form['email']
            user = self.User.query.filter_by(email=email).first()
            if not user:
                user = self.User(email=email)
                self.db.session.add(user)
                self.db.session.commit()
            
            # Generate 6-digit token
            digit_token = ''.join(random.choices(string.digits, k=6))
            new_token = self.Token(user_id=user.id, token=digit_token)
            self.db.session.add(new_token)
            self.db.session.commit()
            
            # Create email message
            msg = Message('Your Login Code',
                          recipients=[email])
            msg.body = f'Your 6-digit login code is: {digit_token}'
            
            # Send email (or log it if in development mode)
            if current_app.config['MAIL_SUPPRESS_SEND']:
                self.logger.info(f"Email to: {email}")
                self.logger.info(f"Subject: {msg.subject}")
                self.logger.info(f"Body: {msg.body}")
            else:
                self.mail.send(msg)
            
            return render_template_string(self.login_template, email_sent=True, email=email)
        
        return render_template_string(self.login_template, email_sent=False)

    def verify_code(self):
        email = request.form['email']
        entered_code = ''.join([request.form.get(f'code{i}', '') for i in range(6)])
        user = self.User.query.filter_by(email=email).first()
        if user:
            token = self.Token.query.filter_by(user_id=user.id).order_by(self.Token.created_at.desc()).first()
            if token and token.token == entered_code:
                if datetime.utcnow() - token.created_at <= timedelta(minutes=10):
                    login_user(user)
                    self.db.session.delete(token)
                    self.db.session.commit()
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('dashboard'))
                else:
                    flash('The code has expired. Please request a new one.', 'error')
            else:
                flash('Invalid code. Please try again.', 'error')
        else:
            flash('User not found.', 'error')
        return redirect(url_for('passwordless.login'))

    def logout(self):
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('passwordless.login'))

    login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Passwordless Auth</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <style>
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .fade-in {
            animation: fadeIn 0.5s ease-out;
        }
        .code-input {
            width: 2.5rem;
            height: 3rem;
            font-size: 1.5rem;
            border: 2px solid #e5e7eb;
            border-radius: 0.5rem;
            text-align: center;
            margin-right: 0.5rem;
            transition: all 0.3s ease;
        }
        .code-input:focus {
            border-color: #000;
            box-shadow: 0 0 0 3px rgba(0, 0, 0, 0.1);
            outline: none;
        }
    </style>
</head>
<body class="bg-white min-h-screen flex items-center justify-center">
    <div class="container max-w-md w-full p-8 fade-in">        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="mb-4 p-4 rounded-md {% if category == 'info' %}bg-gray-100 text-gray-700{% elif category == 'success' %}bg-green-100 text-green-700{% elif category == 'error' %}bg-red-100 text-red-700{% endif %}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% if email_sent %}
            <p class="text-gray-600 mb-6 text-center">Enter the 6-digit code sent to your email:</p>
            <form id="verify-form" method="POST" action="{{ url_for('passwordless.verify_code') }}" class="space-y-6">
                <input type="hidden" name="email" value="{{ email }}">
                <div class="flex justify-center space-x-2">
                    {% for i in range(6) %}
                    <input type="text" name="code{{ i }}" class="code-input" maxlength="1" required pattern="[0-9]" inputmode="numeric" data-index="{{ i }}">
                    {% endfor %}
                </div>
            </form>
            <p class="mt-4 text-center text-sm text-gray-600">
                Didn't receive the code? <a href="{{ url_for('passwordless.login') }}" class="text-black hover:underline">Try again</a>
            </p>
        {% else %}
            <form id="email-form" method="POST" class="space-y-6">
                <div>
                    <input type="email" id="email" name="email" required placeholder="Enter your email" class="mt-1 block w-full border-b border-gray-300 py-2 px-3 focus:outline-none focus:border-black transition duration-300 ease-in-out">
                </div>
                <button type="submit" class="w-full bg-black text-white py-3 px-4 rounded-md hover:bg-gray-800 transition duration-300 ease-in-out">
                    Send Code
                </button>
            </form>
        {% endif %}
    </div>

    <script>
        function handlePaste(e) {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text');
            const digits = paste.replace(/\D/g, '').slice(0, 6);
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

            // Auto focus email field on load
            const emailInput = document.getElementById('email');
            if (emailInput) {
                emailInput.focus();
            }

            // Auto focus first code input when it appears
            const firstCodeInput = document.querySelector('.code-input');
            if (firstCodeInput) {
                firstCodeInput.focus();
            }
        });
    </script>
</body>
</html>
    """