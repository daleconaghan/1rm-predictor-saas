from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
import math

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Handle different database URL formats
database_url = os.environ.get('DATABASE_URL', 'sqlite:///1rm_predictor.db')
if database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+pg8000://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    calculations = db.relationship('OneRMCalculation', backref='user', lazy=True)

class OneRMCalculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    calculated_1rm = db.Column(db.Float, nullable=False)
    formula_used = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    def generate_recommendations(one_rm, exercise, current_weight, current_reps, strength_level):
        recommendations = []
        
        recommendations.append(f"Your estimated 1RM for {exercise.replace('_', ' ').title()}: {one_rm} lbs")
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
            recommendations.append(f"• {goal}: {min_weight}-{max_weight} lbs")
        
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
        recommendations.append(f"\n🎯 Next Goal: {next_goal} lbs (+5%)")
        
        return recommendations

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
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
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Registration successful!')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
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
    if request.method == 'POST':
        exercise = request.form['exercise']
        weight = float(request.form['weight'])
        reps = int(request.form['reps'])
        bodyweight = float(request.form.get('bodyweight', 0)) or None
        
        if reps < 1 or reps > 15:
            flash('Reps must be between 1 and 15 for accurate calculations')
            return redirect(url_for('calculate'))
        
        formulas = OneRMCalculator.calculate_all_formulas(weight, reps)
        average_1rm = OneRMCalculator.get_average_1rm(weight, reps)
        
        strength_level = RecommendationEngine.get_strength_level(
            average_1rm, exercise, bodyweight
        )
        
        recommendations = RecommendationEngine.generate_recommendations(
            average_1rm, exercise, weight, reps, strength_level
        )
        
        calculation = OneRMCalculation(
            user_id=current_user.id,
            exercise=exercise,
            weight=weight,
            reps=reps,
            calculated_1rm=average_1rm,
            formula_used='average'
        )
        db.session.add(calculation)
        db.session.commit()
        
        return render_template('results.html', 
                             formulas=formulas,
                             average_1rm=average_1rm,
                             exercise=exercise,
                             weight=weight,
                             reps=reps,
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
    calculations = OneRMCalculation.query.filter_by(user_id=current_user.id)\
        .order_by(OneRMCalculation.created_at.desc()).all()
    return render_template('history.html', calculations=calculations)

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Database error: {e}")
            print(f"DATABASE_URL: {os.environ.get('DATABASE_URL', 'Not set')}")
    app.run(debug=True)