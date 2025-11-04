#!/bin/bash

# 1RM Predictor - Quick Setup Script
echo "🏋️  1RM Predictor - Local Setup"
echo "================================"
echo ""

# Check Python version
echo "1️⃣  Checking Python version..."
python3 --version

# Install dependencies
echo ""
echo "2️⃣  Installing dependencies..."
pip3 install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Werkzeug python-dotenv bcrypt itsdangerous pytz

# Create .env if it doesn't exist
echo ""
echo "3️⃣  Setting up environment..."
if [ ! -f .env ]; then
    cat > .env << 'ENV'
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
DATABASE_URL=
ENV
    echo "✅ Created .env file"
else
    echo "✅ .env file already exists"
fi

# Initialize database
echo ""
echo "4️⃣  Initializing database..."
python3 << 'PYTHON'
from app import app, db
with app.app_context():
    db.create_all()
    print("✅ Database created at instance/1rm_predictor.db")
PYTHON

# Create demo user with test data
echo ""
echo "5️⃣  Creating demo user and test data..."
python3 << 'PYTHON'
from app import app, db, User, OneRMCalculation, Workout
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta, UTC

with app.app_context():
    # Check if demo user exists
    user = User.query.filter_by(username='demo').first()

    if user:
        print("⚠️  Demo user already exists")
    else:
        # Create demo user
        user = User(
            username='demo',
            email='demo@example.com',
            password_hash=generate_password_hash('demo123'),
            email_verified=True,
            subscription_tier='pro'
        )
        db.session.add(user)
        db.session.commit()
        print("✅ Created user: demo (password: demo123)")

        # Create progressive calculations over 120 days
        exercises = [
            ('bench_press', 200, 5),
            ('squat', 300, 5),
            ('deadlift', 350, 5),
            ('overhead_press', 135, 5)
        ]

        calc_count = 0
        for exercise, base_weight, reps in exercises:
            for i in range(8):
                calc = OneRMCalculation(
                    user_id=user.id,
                    exercise=exercise,
                    weight=base_weight + (i * 10),
                    reps=reps,
                    calculated_1rm=(base_weight + (i * 10)) * 1.15,
                    formula_used='average',
                    weight_unit='lbs',
                    created_at=datetime.now(UTC) - timedelta(days=120 - (i * 15))
                )
                db.session.add(calc)
                calc_count += 1

        # Create workout logs
        workout_count = 0
        for i in range(20):
            workout = Workout(
                user_id=user.id,
                exercise='bench_press',
                weight=200 + (i % 5) * 10,
                reps=5,
                effort=[1, 2, 2, 3, 3][i % 5],
                created_at=datetime.now(UTC) - timedelta(days=40 - (i * 2))
            )
            db.session.add(workout)
            workout_count += 1

        db.session.commit()
        print(f"✅ Created {calc_count} calculations and {workout_count} workout logs")

PYTHON

# Display login info
echo ""
echo "================================"
echo "✅ Setup Complete!"
echo "================================"
echo ""
echo "📝 Login Credentials:"
echo "   Username: demo"
echo "   Password: demo123"
echo ""
echo "🚀 To start the app, run:"
echo "   python3 app.py"
echo ""
echo "Then visit: http://localhost:5000"
echo ""
echo "🧠 To see ML Insights:"
echo "   1. Login with demo/demo123"
echo "   2. Click 'ML Insights' in navigation"
echo "   3. View your progress analysis!"
echo ""
