from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import click
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from datetime import UTC, datetime, timedelta, timezone
import pytz
from itsdangerous import URLSafeTimedSerializer
import os
import warnings
from dotenv import load_dotenv
import math
import time
from collections import defaultdict, deque

load_dotenv()

app = Flask(__name__)
DEFAULT_SECRET_KEY = 'dev-secret-key-change-in-production'

# Determine environment to decide on security defaults
env_name = (app.config.get('ENV') or os.environ.get('FLASK_ENV') or os.environ.get('ENV') or 'production').lower()
is_dev_environment = env_name in ('development', 'testing') or bool(app.config.get('TESTING'))

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if is_dev_environment:
        warnings.warn(
            'SECRET_KEY environment variable is not set; falling back to a development key. '
            'Never use this fallback in production.',
            RuntimeWarning,
        )
        secret_key = DEFAULT_SECRET_KEY
    else:
        raise RuntimeError('SECRET_KEY environment variable must be set for non-development environments.')
app.config['SECRET_KEY'] = secret_key

csrf = CSRFProtect()
csrf.init_app(app)


def _generate_csrf_token():
    if not app.config.get('WTF_CSRF_ENABLED', True):
        return ''
    return generate_csrf()


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': _generate_csrf_token}

# Use SQLite for reliable deployment (perfect for micro-SaaS)
if os.environ.get('DATABASE_URL'):
    # Convert postgresql:// to postgresql+psycopg:// for psycopg3
    database_url = os.environ.get('DATABASE_URL')
    if database_url.startswith('postgresql://'):
        database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Local development
    database_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', '1rm_predictor.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'

# Note: SQLite handles thousands of users perfectly for a 1RM calculator
# Can migrate to PostgreSQL later when needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure session timeout for remember me functionality
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

# Session configuration for proper login persistence
app.config['SESSION_COOKIE_SECURE'] = not is_dev_environment
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
if not is_dev_environment:
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail_credentials_configured = all([
    app.config.get('MAIL_USERNAME'),
    app.config.get('MAIL_PASSWORD'),
    app.config.get('MAIL_DEFAULT_SENDER'),
])
app.config['MAIL_ENABLED'] = mail_credentials_configured
if not mail_credentials_configured:
    warnings.warn(
        'Mail credentials are not fully configured; verification and password reset emails will not be sent.',
        RuntimeWarning,
    )

if not is_dev_environment:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    @app.before_request
    def enforce_https_in_production():
        if app.config.get('TESTING'):
            return
        if request.is_secure:
            return
        if request.headers.get('X-Forwarded-Proto', '').lower().startswith('https'):
            return
        host = request.host.split(':', 1)[0]
        if host in {'localhost', '127.0.0.1', '0.0.0.0'}:
            return
        if request.method in {'GET', 'HEAD', 'OPTIONS'}:
            secure_url = request.url.replace('http://', 'https://', 1)
            return redirect(secure_url, code=301)


@app.after_request
def apply_security_headers(response):
    if not is_dev_environment:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.before_request
def ensure_session_validity():
    if not current_user.is_authenticated:
        return

    password_changed_at = ensure_aware(current_user.password_changed_at) or datetime.fromtimestamp(0, tz=UTC)
    session_value = session.get('password_changed_at')
    session_timestamp = None
    if session_value:
        try:
            session_timestamp = datetime.fromisoformat(session_value)
            if session_timestamp.tzinfo is None:
                session_timestamp = session_timestamp.replace(tzinfo=UTC)
        except Exception:
            session_timestamp = None

    if not session_timestamp or session_timestamp < password_changed_at:
        session.pop('password_changed_at', None)
        logout_user()
        flash('Your session has expired. Please log in again.', 'warning')
        return redirect(url_for('login'))


@app.template_filter('localtime')
def localtime_filter(utc_dt, fmt='%m/%d/%Y %I:%M %p'):
    """Convert UTC datetime to user's local time for display"""
    if utc_dt is None:
        return ''
    
    # Add UTC timezone info to the datetime if it doesn't have one
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    
    # Get user's timezone from session, default to UTC+1
    user_timezone_name = session.get('user_timezone', 'Europe/London')
    
    try:
        # Try to use pytz for better timezone handling
        user_tz = pytz.timezone(user_timezone_name)
        local_dt = utc_dt.astimezone(user_tz)
    except:
        # Fallback to manual UTC+1 offset
        user_tz = timezone(timedelta(hours=1))
        local_dt = utc_dt.astimezone(user_tz)
    
    # Return formatted string
    return local_dt.strftime(fmt)

# Initialize URL serializer for email tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize database tables
def init_db():
    """Initialize database tables."""
    with app.app_context():
        db.create_all()


def current_utc_time():
    """Return a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_aware(dt):
    """Ensure a datetime is timezone-aware (UTC)."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class SimpleRateLimiter:
    """Minimal in-memory rate limiter keyed by string identifiers."""

    def __init__(self):
        self._attempts = defaultdict(deque)

    def allow(self, key, limit, window_seconds):
        now = time.monotonic()
        attempts = self._attempts[key]
        while attempts and now - attempts[0] > window_seconds:
            attempts.popleft()
        if len(attempts) >= limit:
            return False
        attempts.append(now)
        return True


def _client_identifier():
    """Return a stable identifier for the current client for rate limiting."""
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr or 'unknown'


rate_limiter = SimpleRateLimiter()

RATE_LIMITS = {
    'register': (5, 300),        # 5 attempts per 5 minutes
    'login': (10, 300),          # 10 attempts per 5 minutes
    'password_reset': (5, 900),  # 5 attempts per 15 minutes
}


def enforce_rate_limit(action):
    """Apply configured rate limit for the given action."""
    limit, window = RATE_LIMITS[action]
    key = f"{action}:{_client_identifier()}"
    return rate_limiter.allow(key, limit, window)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    password_changed_at = db.Column(db.DateTime(timezone=True), default=current_utc_time, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=current_utc_time)
    
    # Subscription fields
    subscription_tier = db.Column(db.String(20), default='free')  # free, pro, coach
    subscription_status = db.Column(db.String(20), default='active')  # active, cancelled, expired
    subscription_expires = db.Column(db.DateTime(timezone=True))
    calculations_used_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime(timezone=True), default=current_utc_time)
    stripe_customer_id = db.Column(db.String(100))
    
    calculations = db.relationship('OneRMCalculation', backref='user', lazy=True)
    
    def get_calculation_limit(self):
        """Get monthly calculation limit based on subscription tier"""
        if self.subscription_tier == 'free':
            return 10
        elif self.subscription_tier == 'pro':
            return 999999  # unlimited (high number)
        elif self.subscription_tier == 'coach':
            return 999999  # unlimited
        return 10  # default to free
    
    def can_calculate(self):
        """Check if user can make another calculation"""
        # Reset monthly counter if needed
        now = current_utc_time()
        last_reset = ensure_aware(self.last_reset_date)
        if last_reset and (now - last_reset).days >= 30:
            self.calculations_used_this_month = 0
            self.last_reset_date = now
            db.session.commit()
        
        return self.calculations_used_this_month < self.get_calculation_limit()
    
    def increment_calculations(self):
        """Increment calculation count"""
        self.calculations_used_this_month += 1
        # Don't commit here - let the caller handle the transaction

class OneRMCalculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    calculated_1rm = db.Column(db.Float, nullable=False)
    formula_used = db.Column(db.String(50), nullable=False)
    weight_unit = db.Column(db.String(10), default='lbs')
    created_at = db.Column(db.DateTime(timezone=True), default=current_utc_time)

class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    effort = db.Column(db.Integer)  # 1=easy, 2=medium, 3=hard
    created_at = db.Column(db.DateTime(timezone=True), default=current_utc_time)

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

def send_verification_email(user):
    """Send email verification email"""
    if not app.config.get('MAIL_ENABLED'):
        app.logger.warning('Verification email not sent for %s: mail is not configured.', user.email)
        return False
    
    token = serializer.dumps(user.email, salt='email-verification')
    verification_url = url_for('verify_email', token=token, _external=True)
    
    msg = Message(
        subject='Verify Your Email - 1RM Predictor',
        recipients=[user.email],
        html=f'''
        <h2>Welcome to 1RM Predictor!</h2>
        <p>Hi {user.username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}">Verify Email Address</a></p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create this account, please ignore this email.</p>
        '''
    )
    
    try:
        mail.send(msg)
        app.logger.info('Verification email sent to %s', user.email)
        return True
    except Exception as e:
        app.logger.error('Failed to send verification email to %s: %s', user.email, e)
        return False

def send_password_reset_email(user):
    """Send password reset email"""
    if not app.config.get('MAIL_ENABLED'):
        app.logger.warning('Password reset email not sent for %s: mail is not configured.', user.email)
        return False

    issued_at = int(current_utc_time().timestamp())
    token = serializer.dumps({'email': user.email, 'iat': issued_at}, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)
    
    msg = Message(
        subject='Password Reset - 1RM Predictor',
        recipients=[user.email],
        html=f'''
        <h2>Password Reset Request</h2>
        <p>Hi {user.username},</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="{reset_url}">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
        '''
    )
    
    try:
        mail.send(msg)
        app.logger.info('Password reset email sent to %s', user.email)
        return True
    except Exception as e:
        app.logger.error('Failed to send password reset email to %s: %s', user.email, e)
        return False

class OneRMCalculator:
    @staticmethod
    def epley_formula(weight, reps):
        if reps == 1:
            return weight
        return weight * (1 + reps / 30)
    
    @staticmethod
    def brzycki_formula(weight, reps):
        if reps == 1:
            return weight
        return weight / (1.0278 - 0.0278 * reps)
    
    @staticmethod
    def lander_formula(weight, reps):
        if reps == 1:
            return weight
        return weight / (1.013 - 0.0267123 * reps)
    
    @staticmethod
    def lombardi_formula(weight, reps):
        if reps == 1:
            return weight
        return weight * (reps ** 0.10)
    
    @staticmethod
    def mayhew_formula(weight, reps):
        if reps == 1:
            return weight
        return (100 * weight) / (52.2 + 41.9 * math.exp(-0.055 * reps))
    
    @staticmethod
    def calculate_all_formulas(weight, reps):
        return {
            'epley': round(OneRMCalculator.epley_formula(weight, reps), 1),
            'brzycki': round(OneRMCalculator.brzycki_formula(weight, reps), 1),
            'lander': round(OneRMCalculator.lander_formula(weight, reps), 1),
            'lombardi': round(OneRMCalculator.lombardi_formula(weight, reps), 1),
            'mayhew': round(OneRMCalculator.mayhew_formula(weight, reps), 1)
        }
    
    @staticmethod
    def get_average_1rm(weight, reps):
        formulas = OneRMCalculator.calculate_all_formulas(weight, reps)
        return round(sum(formulas.values()) / len(formulas), 1)

class RecommendationEngine:
    @staticmethod
    def get_strength_level(one_rm, exercise, bodyweight=None):
        standards = {
            'bench_press': {
                'beginner': 0.75,
                'novice': 1.0,
                'intermediate': 1.25,
                'advanced': 1.5,
                'elite': 1.9
            },
            'squat': {
                'beginner': 1.0,
                'novice': 1.25,
                'intermediate': 1.5,
                'advanced': 1.75,
                'elite': 2.0
            },
            'deadlift': {
                'beginner': 1.25,
                'novice': 1.5,
                'intermediate': 1.75,
                'advanced': 2.0,
                'elite': 2.5
            },
            'overhead_press': {
                'beginner': 0.5,
                'novice': 0.65,
                'intermediate': 0.8,
                'advanced': 1.0,
                'elite': 1.2
            }
        }
        
        if not bodyweight or exercise not in standards:
            return 'Unknown'
        
        ratio = one_rm / bodyweight
        exercise_standards = standards[exercise]
        
        if ratio >= exercise_standards['elite']:
            return 'Elite'
        elif ratio >= exercise_standards['advanced']:
            return 'Advanced'
        elif ratio >= exercise_standards['intermediate']:
            return 'Intermediate'
        elif ratio >= exercise_standards['novice']:
            return 'Novice'
        else:
            return 'Beginner'
    
    @staticmethod
    def generate_recommendations(one_rm, exercise, current_weight, current_reps, strength_level, weight_unit='lbs'):
        recommendations = []
        
        unit_label = weight_unit
        recommendations.append(f"Your estimated 1RM for {exercise.replace('_', ' ').title()}: {one_rm} {unit_label}")
        recommendations.append(f"Strength Level: {strength_level}")
        
        percentage_ranges = {
            "Strength (1-3 reps)": (90, 100),
            "Power (3-5 reps)": (85, 95),
            "Hypertrophy (6-12 reps)": (65, 85),
            "Endurance (12+ reps)": (50, 70)
        }
        
        recommendations.append("\n🎯 Training Recommendations:")
        for goal, (min_pct, max_pct) in percentage_ranges.items():
            min_weight = round(one_rm * min_pct / 100, 1)
            max_weight = round(one_rm * max_pct / 100, 1)
            recommendations.append(f"• {goal}: {min_weight}-{max_weight} {unit_label}")
        
        if strength_level == 'Beginner':
            recommendations.append("\n💪 Beginner Tips:")
            recommendations.append("• Focus on form and consistency")
            recommendations.append("• Train 2-3x per week with this exercise")
            recommendations.append("• Progress by 2.5-5 lbs weekly")
        elif strength_level == 'Intermediate':
            recommendations.append("\n🔥 Intermediate Tips:")
            recommendations.append("• Periodize your training")
            recommendations.append("• Include accessory exercises")
            recommendations.append("• Track weekly progress")
        elif strength_level in ['Advanced', 'Elite']:
            recommendations.append("\n🏆 Advanced Tips:")
            recommendations.append("• Use specialized programs")
            recommendations.append("• Focus on competition prep")
            recommendations.append("• Consider coaching")
        
        next_goal = round(one_rm * 1.05, 1)
        recommendations.append(f"\n🎯 Next Goal: {next_goal} {unit_label} (+5%)")
        
        return recommendations

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not enforce_rate_limit('register'):
            flash('Too many registration attempts. Please wait a few minutes and try again.', 'warning')
            return redirect(url_for('register'))

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            email_verified=False
        )
        db.session.add(user)
        db.session.commit()

        if send_verification_email(user):
            flash('Registration successful! Please check your email to verify your account.')
        else:
            flash('Registration successful! We could not send a verification email right now. '
                  'Please try again later or contact support.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not enforce_rate_limit('login'):
            flash('Too many login attempts. Please wait a few minutes and try again.', 'warning')
            return redirect(url_for('login'))

        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me') == 'on'
        user = User.query.filter_by(username=username).first()

        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember_me)
            password_changed_at = ensure_aware(user.password_changed_at) or current_utc_time()
            session['password_changed_at'] = password_changed_at.isoformat()
            flash('Login successful!' + (' You will stay logged in for 30 days.' if remember_me else ''))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=86400)  # 24 hours
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.email_verified = True
            db.session.commit()
            flash('Email verified successfully! You can now login.')
        else:
            flash('Invalid verification link.')
    except Exception:
        flash('Invalid or expired verification link.')
    
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if not enforce_rate_limit('password_reset'):
            flash('Too many password reset requests. Please wait a bit and try again.', 'warning')
            return redirect(url_for('login'))

        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            if not send_password_reset_email(user):
                app.logger.warning('Password reset email could not be sent for %s', email)
        else:
            app.logger.info('Password reset requested for non-existent account: %s', email)

        flash('If the email address is registered, you will receive password reset instructions shortly.')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        token_data = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour
    except Exception:
        flash('Invalid or expired reset link.')
        return redirect(url_for('forgot_password'))

    email = token_data.get('email') if isinstance(token_data, dict) else token_data
    if not email:
        flash('Invalid reset link.')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid reset link.')
        return redirect(url_for('forgot_password'))

    issued_at = None
    if isinstance(token_data, dict):
        issued_raw = token_data.get('iat')
        if issued_raw is not None:
            try:
                issued_at = datetime.fromtimestamp(int(issued_raw), tz=UTC)
            except Exception:
                issued_at = None

    if issued_at is not None:
        password_changed_at = ensure_aware(user.password_changed_at) or datetime.fromtimestamp(0, tz=UTC)
        if issued_at < password_changed_at:
            flash('Invalid or expired reset link.')
            return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)
        
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = current_utc_time()
        db.session.commit()
        session.pop('password_changed_at', None)
        if current_user.is_authenticated and current_user.id == user.id:
            logout_user()

        flash('Password reset successful! You can now login.')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('password_changed_at', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    recent_calculations = OneRMCalculation.query.filter_by(user_id=current_user.id)\
        .order_by(OneRMCalculation.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', calculations=recent_calculations)

@app.route('/calculate', methods=['GET', 'POST'])
@login_required
def calculate():
    # Check calculation limit before processing
    if not current_user.can_calculate():
        flash(f'You have reached your monthly limit of {current_user.get_calculation_limit()} calculations. Upgrade to Pro for unlimited calculations!', 'warning')
        return redirect(url_for('pricing'))
    
    if request.method == 'POST':
        exercise = request.form['exercise']
        custom_exercise = request.form.get('custom_exercise', '').strip()
        weight_unit = request.form['weight_unit']
        weight = float(request.form['weight'])
        reps = int(request.form['reps'])
        bodyweight_str = request.form.get('bodyweight', '').strip()
        bodyweight = float(bodyweight_str) if bodyweight_str else None
        
        # Handle custom exercise
        if exercise == 'custom' and custom_exercise:
            exercise = custom_exercise.lower().replace(' ', '_')
        
        # Convert weight to lbs for calculations (formulas are calibrated for lbs)
        if weight_unit == 'kg':
            weight_lbs = weight * 2.20462  # Convert kg to lbs
            if bodyweight:
                bodyweight_lbs = bodyweight * 2.20462
            else:
                bodyweight_lbs = None
        else:
            weight_lbs = weight
            bodyweight_lbs = bodyweight
        
        if reps < 1 or reps > 15:
            flash('Reps must be between 1 and 15 for accurate calculations')
            return redirect(url_for('calculate'))
        
        # Calculate 1RM using converted weight
        formulas = OneRMCalculator.calculate_all_formulas(weight_lbs, reps)
        average_1rm_lbs = OneRMCalculator.get_average_1rm(weight_lbs, reps)
        
        # Convert results back to user's preferred unit
        if weight_unit == 'kg':
            formulas_display = {k: round(v / 2.20462, 1) for k, v in formulas.items()}
            average_1rm_display = round(average_1rm_lbs / 2.20462, 1)
        else:
            formulas_display = formulas
            average_1rm_display = average_1rm_lbs
        
        strength_level = RecommendationEngine.get_strength_level(
            average_1rm_lbs, exercise, bodyweight_lbs
        )
        
        recommendations = RecommendationEngine.generate_recommendations(
            average_1rm_display, exercise, weight, reps, strength_level, weight_unit
        )
        
        calculation = OneRMCalculation(
            user_id=current_user.id,
            exercise=exercise,
            weight=weight,
            reps=reps,
            calculated_1rm=average_1rm_display,
            formula_used='average',
            weight_unit=weight_unit
        )
        db.session.add(calculation)
        
        # Increment calculation counter
        current_user.increment_calculations()
        
        db.session.commit()
        
        return render_template('results.html', 
                             formulas=formulas_display,
                             average_1rm=average_1rm_display,
                             exercise=exercise,
                             weight=weight,
                             reps=reps,
                             weight_unit=weight_unit,
                             strength_level=strength_level,
                             recommendations=recommendations)
    
    return render_template('calculate.html')

@app.route('/api/calculate', methods=['POST'])
@login_required
def api_calculate():
    if not current_user.can_calculate():
        limit = current_user.get_calculation_limit()
        return jsonify({
            'success': False,
            'error': f'Monthly limit reached. You can perform {limit} calculations per month on your current plan.'
        }), 403

    data = request.get_json() or {}

    try:
        exercise = data['exercise']
        custom_exercise = data.get('custom_exercise', '').strip()
        weight = float(data['weight'])
        reps = int(data['reps'])
        weight_unit = data.get('weight_unit', 'lbs')
        bodyweight_raw = data.get('bodyweight')

        if weight <= 0:
            raise ValueError('Weight must be greater than zero.')

        if reps < 1 or reps > 15:
            raise ValueError('Reps must be between 1 and 15 for accurate calculations.')

        if weight_unit not in ('lbs', 'kg'):
            raise ValueError("Invalid weight_unit provided. Use 'lbs' or 'kg'.")

        bodyweight = None
        if bodyweight_raw not in (None, ''):
            bodyweight = float(bodyweight_raw)
            if bodyweight <= 0:
                raise ValueError('Bodyweight must be greater than zero.')

        if exercise == 'custom' and custom_exercise:
            exercise = custom_exercise.lower().replace(' ', '_')

        if weight_unit == 'kg':
            weight_lbs = weight * 2.20462
            bodyweight_lbs = bodyweight * 2.20462 if bodyweight is not None else None
        else:
            weight_lbs = weight
            bodyweight_lbs = bodyweight

        formulas_lbs = OneRMCalculator.calculate_all_formulas(weight_lbs, reps)
        average_1rm_lbs = OneRMCalculator.get_average_1rm(weight_lbs, reps)

        if weight_unit == 'kg':
            formulas_display = {k: round(v / 2.20462, 1) for k, v in formulas_lbs.items()}
            average_1rm_display = round(average_1rm_lbs / 2.20462, 1)
        else:
            formulas_display = formulas_lbs
            average_1rm_display = average_1rm_lbs

        strength_level = RecommendationEngine.get_strength_level(
            average_1rm_lbs, exercise, bodyweight_lbs
        )

        recommendations = RecommendationEngine.generate_recommendations(
            average_1rm_display, exercise, weight, reps, strength_level, weight_unit
        )

        calculation = OneRMCalculation(
            user_id=current_user.id,
            exercise=exercise,
            weight=weight,
            reps=reps,
            calculated_1rm=average_1rm_display,
            formula_used='average',
            weight_unit=weight_unit
        )
        db.session.add(calculation)
        current_user.increment_calculations()
        db.session.commit()

        return jsonify({
            'success': True,
            'formulas': formulas_display,
            'average_1rm': average_1rm_display,
            'strength_level': strength_level,
            'recommendations': recommendations,
            'weight_unit': weight_unit
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/history')
@login_required
def history():
    calculations = OneRMCalculation.query.filter_by(user_id=current_user.id)\
        .order_by(OneRMCalculation.created_at.desc()).all()
    return render_template('history.html', calculations=calculations)

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/set-timezone', methods=['POST'])
def set_timezone():
    """Store user's timezone in session"""
    try:
        data = request.get_json()
        timezone_name = data.get('timezone')

        if timezone_name:
            # Validate timezone name
            try:
                pytz.timezone(timezone_name)
                session['user_timezone'] = timezone_name
                session.permanent = True

                return jsonify({
                    'success': True,
                    'timezone': timezone_name,
                    'reload': True  # Tell frontend to reload for updated times
                })
            except:
                return jsonify({'success': False, 'error': 'Invalid timezone'})

        return jsonify({'success': False, 'error': 'No timezone provided'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/log-workout', methods=['GET', 'POST'])
@login_required
def log_workout():
    if request.method == 'POST':
        exercise = request.form['exercise']
        weight = float(request.form['weight'])
        reps = int(request.form['reps'])
        effort = int(request.form.get('effort', 2))

        workout = Workout(
            user_id=current_user.id,
            exercise=exercise,
            weight=weight,
            reps=reps,
            effort=effort
        )
        db.session.add(workout)
        db.session.commit()

        flash('Workout logged successfully!')
        return redirect(url_for('my_workouts'))

    return render_template('log_workout.html')

@app.route('/my-workouts')
@login_required
def my_workouts():
    workouts = Workout.query.filter_by(user_id=current_user.id)\
        .order_by(Workout.created_at.desc()).all()
    return render_template('my_workouts.html', workouts=workouts)

@app.route('/ml-insights')
@login_required
def ml_insights():
    # Calculate features from workout history
    # Call your ML API
    # Show predictions with disclaimers
    pass

@app.cli.command('migrate-db')
def migrate_db_command():
    """Change the stored password hash column to VARCHAR(255)."""
    engine = db.engine
    if engine.url.get_backend_name() == 'sqlite':
        click.echo('Skipping migrate-db: column alteration is not supported on SQLite.')
        return

    with engine.begin() as connection:
        connection.execute(db.text('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(255);'))
    click.echo('Database migration successful!')


@app.cli.command('init-db')
def init_db_command():
    """Initialize database tables."""
    init_db()
    click.echo('Database tables initialized.')

@app.cli.command('force-migrate')
def force_migrate_command():
    """Force recreate all database tables (WARNING: deletes all data)."""
    click.confirm('This will delete all existing data. Continue?', abort=True)
    db.drop_all()
    db.create_all()
    click.echo('✅ Database force migration complete! All tables recreated with subscription fields.')

@app.cli.command('safe-migrate')
def safe_migrate_command():
    """Add subscription columns without deleting existing data."""
    statements = [
        'ALTER TABLE "user" ADD COLUMN subscription_tier VARCHAR(20) DEFAULT \'free\';',
        'ALTER TABLE "user" ADD COLUMN subscription_status VARCHAR(20) DEFAULT \'active\';',
        'ALTER TABLE "user" ADD COLUMN subscription_expires TIMESTAMP;',
        'ALTER TABLE "user" ADD COLUMN calculations_used_this_month INTEGER DEFAULT 0;',
        'ALTER TABLE "user" ADD COLUMN last_reset_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;',
        'ALTER TABLE "user" ADD COLUMN stripe_customer_id VARCHAR(100);',
        'ALTER TABLE "user" ADD COLUMN password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;',
        'ALTER TABLE "one_rm_calculation" ADD COLUMN weight_unit VARCHAR(10) DEFAULT \'lbs\';'
    ]

    with db.engine.begin() as connection:
        for stmt in statements:
            try:
                connection.execute(db.text(stmt))
            except Exception:
                # Ignore if column already exists
                pass

    click.echo('✅ Safe migration complete! New subscription, security, and weight unit fields added.')


@app.cli.command('fix-naive-datetimes')
def fix_naive_datetimes_command():
    """Ensure stored datetimes are UTC-aware."""
    engine = db.engine
    if engine.url.get_backend_name() == 'sqlite':
        click.echo('Skipping fix-naive-datetimes: SQLite does not preserve timezone info.')
        return

    fixed_users = 0
    fixed_calculations = 0
    needs_commit = False

    # Iterate through users
    for user in User.query.all():
        changed = False

        new_created_at = ensure_aware(user.created_at)
        if new_created_at is not user.created_at:
            user.created_at = new_created_at
            changed = True

        new_last_reset = ensure_aware(user.last_reset_date)
        if new_last_reset is not user.last_reset_date:
            user.last_reset_date = new_last_reset
            changed = True

        new_expires = ensure_aware(user.subscription_expires)
        if new_expires is not user.subscription_expires:
            user.subscription_expires = new_expires
            changed = True

        new_password_changed = ensure_aware(user.password_changed_at)
        if new_password_changed is not user.password_changed_at:
            user.password_changed_at = new_password_changed
            changed = True

        if changed:
            fixed_users += 1
            needs_commit = True

    # Iterate through calculations
    for calc in OneRMCalculation.query.all():
        new_created_at = ensure_aware(calc.created_at)
        if new_created_at is not calc.created_at:
            calc.created_at = new_created_at
            fixed_calculations += 1
            needs_commit = True

    if needs_commit:
        db.session.commit()

    click.echo(f'Updated {fixed_users} users and {fixed_calculations} calculations.')

# Debug routes removed for production

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Database error: {e}")
            print(f"DATABASE_URL: {os.environ.get('DATABASE_URL', 'Not set')}")
    
    # Use PORT from environment for Railway deployment
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
