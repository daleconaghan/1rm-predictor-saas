from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv
import math

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

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
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.template_filter('localtime')
def localtime_filter(utc_dt, fmt='%m/%d/%Y %I:%M %p'):
    """Convert UTC datetime to user's local time for display"""
    if utc_dt is None:
        return ''
    
    # Add UTC timezone info to the datetime if it doesn't have one
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    
    # Convert to user's timezone (UTC+1)
    user_tz = timezone(timedelta(hours=1))  # CET/BST (UTC+1)
    local_dt = utc_dt.astimezone(user_tz)
    
    # Return formatted string
    return local_dt.strftime(fmt)

# Initialize URL serializer for email tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize database tables
def init_db():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            print("Database tables initialized")
    except Exception as e:
        print(f"Database initialization failed: {e}")

# Call initialization only if not in production startup
if __name__ == '__main__':
    init_db()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Subscription fields
    subscription_tier = db.Column(db.String(20), default='free')  # free, pro, coach
    subscription_status = db.Column(db.String(20), default='active')  # active, cancelled, expired
    subscription_expires = db.Column(db.DateTime)
    calculations_used_this_month = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
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
        now = datetime.utcnow()
        if self.last_reset_date and (now - self.last_reset_date).days >= 30:
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    try:
        # Ensure tables exist before any database operations
        db.create_all()
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

def send_verification_email(user):
    """Send email verification email"""
    if not app.config.get('MAIL_USERNAME'):
        print("Email not configured - verification email not sent")
        return
    
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
        print(f"Verification email sent to {user.email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_password_reset_email(user):
    """Send password reset email"""
    if not app.config.get('MAIL_USERNAME'):
        print("Email not configured - reset email not sent")
        return
    
    token = serializer.dumps(user.email, salt='password-reset')
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
        print(f"Password reset email sent to {user.email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

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
    try:
        db.create_all()
    except Exception as e:
        print(f"Database error on index: {e}")
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Ensure tables exist before any database operations
    db.create_all()
    
    if request.method == 'POST':
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
        
        send_verification_email(user)
        flash('Registration successful! Please check your email to verify your account.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Ensure tables exist
    db.create_all()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me') == 'on'
        user = User.query.filter_by(username=username).first()
        
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember_me)
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
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            send_password_reset_email(user)
            flash('Password reset instructions sent to your email.')
        else:
            flash('Email address not found.')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour
    except Exception:
        flash('Invalid or expired reset link.')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid reset link.')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)
        
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password reset successful! You can now login.')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Ensure tables exist
    db.create_all()
    recent_calculations = OneRMCalculation.query.filter_by(user_id=current_user.id)\
        .order_by(OneRMCalculation.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', calculations=recent_calculations)

@app.route('/calculate', methods=['GET', 'POST'])
@login_required
def calculate():
    # Ensure tables exist
    db.create_all()
    
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
    data = request.get_json()
    
    try:
        exercise = data['exercise']
        weight = float(data['weight'])
        reps = int(data['reps'])
        bodyweight = data.get('bodyweight')
        
        if bodyweight:
            bodyweight = float(bodyweight)
        
        formulas = OneRMCalculator.calculate_all_formulas(weight, reps)
        average_1rm = OneRMCalculator.get_average_1rm(weight, reps)
        
        strength_level = RecommendationEngine.get_strength_level(
            average_1rm, exercise, bodyweight
        )
        
        recommendations = RecommendationEngine.generate_recommendations(
            average_1rm, exercise, weight, reps, strength_level
        )
        
        return jsonify({
            'success': True,
            'formulas': formulas,
            'average_1rm': average_1rm,
            'strength_level': strength_level,
            'recommendations': recommendations
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/history')
@login_required
def history():
    # Ensure tables exist
    db.create_all()
    calculations = OneRMCalculation.query.filter_by(user_id=current_user.id)\
        .order_by(OneRMCalculation.created_at.desc()).all()
    return render_template('history.html', calculations=calculations)

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/migrate-db')
def migrate_db():
    try:
        with db.engine.connect() as connection:
            connection.execute(db.text('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(255);'))
            connection.commit()
        return "Database migration successful!"
    except Exception as e:
        return f"Migration failed: {e}"

@app.route('/force-migrate')
def force_migrate():
    """Force recreate all database tables - WARNING: Deletes all data"""
    try:
        with app.app_context():
            # Drop all tables (deletes all data)
            db.drop_all()
            
            # Recreate all tables with new schema
            db.create_all()
            
            return "✅ Database force migration complete! All tables recreated with subscription fields."
    except Exception as e:
        return f"❌ Force migration failed: {e}"

@app.route('/safe-migrate')  
def safe_migrate():
    """Add new subscription columns without deleting existing data"""
    try:
        with db.engine.connect() as connection:
            # Add subscription fields one by one
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN subscription_tier VARCHAR(20) DEFAULT \'free\';'))
            except:
                pass  # Column might already exist
            
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN subscription_status VARCHAR(20) DEFAULT \'active\';'))
            except:
                pass
                
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN subscription_expires TIMESTAMP;'))
            except:
                pass
                
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN calculations_used_this_month INTEGER DEFAULT 0;'))
            except:
                pass
                
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN last_reset_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;'))
            except:
                pass
                
            try:
                connection.execute(db.text('ALTER TABLE "user" ADD COLUMN stripe_customer_id VARCHAR(100);'))
            except:
                pass
            
            # Add weight_unit field to calculations table
            try:
                connection.execute(db.text('ALTER TABLE "one_rm_calculation" ADD COLUMN weight_unit VARCHAR(10) DEFAULT \'lbs\';'))
            except:
                pass
                
            connection.commit()
            
        return "✅ Safe migration complete! New subscription and weight unit fields added."
    except Exception as e:
        return f"❌ Safe migration failed: {e}"

# Debug routes removed for production

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Database error: {e}")
            print(f"DATABASE_URL: {os.environ.get('DATABASE_URL', 'Not set')}")
    app.run(host='0.0.0.0', port=5001, debug=True)