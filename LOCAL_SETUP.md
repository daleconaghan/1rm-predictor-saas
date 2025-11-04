# Running 1RM Predictor Locally

## Prerequisites

- Python 3.11+ installed
- pip (Python package manager)
- A terminal/command prompt

## Quick Start (5 minutes)

### 1. Install Dependencies

```bash
cd /home/user/1rm-predictor-saas
pip install -r requirements.txt
```

**Note**: If Flask-Mail fails to install, that's okay - it's optional for email features.

### 2. Set Up Environment Variables

Create a `.env` file:

```bash
cp .env.example .env
```

Or create `.env` manually with:

```env
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
DATABASE_URL=
```

### 3. Initialize the Database

```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all(); print('✅ Database initialized!')"
```

This creates a SQLite database at `instance/1rm_predictor.db`

### 4. Run the Application

```bash
python3 app.py
```

You should see:

```
 * Running on http://127.0.0.1:5000
 * Running on http://0.0.0.0:5000
```

### 5. Open in Browser

Visit: **http://localhost:5000**

---

## Creating Test Data for ML Insights

The ML Insights feature requires at least 2 calculations. Here's how to create test data:

### Option 1: Manual Testing (Recommended for First Time)

1. **Register a new account**:
   - Go to http://localhost:5000/register
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `password123`

2. **Create multiple calculations** (need at least 2):
   - Go to "Calculate" in the navigation
   - Enter different workouts over time:
     - **Workout 1**: Bench Press, 200 lbs, 5 reps
     - **Workout 2**: Bench Press, 210 lbs, 5 reps (do this a day later)
     - **Workout 3**: Squat, 300 lbs, 5 reps
     - **Workout 4**: Deadlift, 350 lbs, 5 reps

3. **Log some workouts** (optional but recommended):
   - Go to "Log Workout"
   - Add a few bench press, squat, or deadlift sessions
   - Vary the effort levels (Easy/Medium/Hard)

4. **View ML Insights**:
   - Click "🧠 ML Insights" in the navigation
   - You'll see progress velocity, predictions, plateau detection, etc.

### Option 2: Quick Script to Populate Test Data

Run this Python script to create realistic test data:

```bash
python3 <<'EOF'
from app import app, db, User, OneRMCalculation, Workout
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta, UTC

with app.app_context():
    # Create test user
    user = User.query.filter_by(username='demo').first()
    if not user:
        user = User(
            username='demo',
            email='demo@example.com',
            password_hash=generate_password_hash('demo123'),
            email_verified=True,
            subscription_tier='pro'
        )
        db.session.add(user)
        db.session.commit()
        print(f"✅ Created user: demo (password: demo123)")

    # Create progressive calculations over 120 days
    exercises = [
        ('bench_press', 200, 5),
        ('squat', 300, 5),
        ('deadlift', 350, 5),
        ('overhead_press', 135, 5)
    ]

    for exercise, base_weight, reps in exercises:
        for i in range(8):
            calc = OneRMCalculation(
                user_id=user.id,
                exercise=exercise,
                weight=base_weight + (i * 10),  # Progressive overload
                reps=reps,
                calculated_1rm=base_weight + (i * 10) * 1.15,
                formula_used='average',
                weight_unit='lbs',
                created_at=datetime.now(UTC) - timedelta(days=120 - (i * 15))
            )
            db.session.add(calc)

    # Create workout logs
    for i in range(20):
        workout = Workout(
            user_id=user.id,
            exercise='bench_press',
            weight=200 + (i % 5) * 10,
            reps=5,
            effort=[1, 2, 2, 3, 3][i % 5],  # Varied effort
            created_at=datetime.now(UTC) - timedelta(days=40 - (i * 2))
        )
        db.session.add(workout)

    db.session.commit()
    print("✅ Created 32 calculations and 20 workout logs")
    print("\nLogin with:")
    print("  Username: demo")
    print("  Password: demo123")
    print("\nThen visit: http://localhost:5000/ml-insights")
EOF
```

---

## Accessing Features

Once running, you can access:

- **Homepage**: http://localhost:5000
- **Register**: http://localhost:5000/register
- **Login**: http://localhost:5000/login
- **Calculator**: http://localhost:5000/calculate
- **Dashboard**: http://localhost:5000/dashboard
- **History**: http://localhost:5000/history
- **Log Workout**: http://localhost:5000/log-workout
- **My Workouts**: http://localhost:5000/my-workouts
- **ML Insights**: http://localhost:5000/ml-insights ⭐ (NEW!)
- **Pricing**: http://localhost:5000/pricing

---

## Troubleshooting

### Port Already in Use

If port 5000 is taken:

```bash
# Kill existing process
lsof -ti:5000 | xargs kill -9

# Or run on different port
export FLASK_RUN_PORT=8080
python3 app.py
```

### Database Errors

Reset the database:

```bash
rm -rf instance/
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Import Errors

Make sure you're in the project directory:

```bash
cd /home/user/1rm-predictor-saas
```

### Dependencies Not Installing

Install core packages individually:

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Werkzeug python-dotenv bcrypt itsdangerous pytz
```

---

## Testing ML Insights Specifically

To see all ML Insights features, you need:

1. **Minimum 2 calculations** (better with 5+)
2. **Multiple exercises** (bench, squat, deadlift, OHP)
3. **Calculations over time** (spread across weeks/months)
4. **Optional**: Workout logs for volume analysis

The demo script above creates ideal test data showing:
- ✅ Progress velocity (gaining ~10 lbs every 15 days)
- ✅ Future predictions (30/60/90 day forecasts)
- ✅ Plateau detection (shows "progressing")
- ✅ Strength balance (compares bench:squat:deadlift:OHP ratios)
- ✅ Volume trends (20 workouts with effort distribution)
- ✅ Personal records (highest 1RM for each exercise)

---

## Running Tests

To verify everything works:

```bash
# Run all tests
python -m unittest tests.test_app -v

# Run specific ML insights tests
python -m unittest tests.test_app.AppTestCase.test_ml_insights_progress_velocity -v
python -m unittest tests.test_app.AppTestCase.test_ml_insights_predict_future_1rm -v
python -m unittest tests.test_app.AppTestCase.test_ml_insights_detect_plateau -v
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key-change-in-production` | Flask secret key |
| `FLASK_ENV` | `production` | Set to `development` for debug mode |
| `DATABASE_URL` | SQLite in `instance/` | PostgreSQL URL for production |
| `MAIL_SERVER` | `smtp.gmail.com` | SMTP server (optional) |
| `MAIL_USERNAME` | - | Email username (optional) |
| `MAIL_PASSWORD` | - | Email password (optional) |

---

## Next Steps

After running locally:

1. **Test the ML Insights** with the demo account
2. **Try creating your own calculations** to see real-time updates
3. **Explore the strength balance** feature with multiple lifts
4. **Check plateau detection** by entering the same weight multiple times

Enjoy your new ML-powered 1RM tracker! 🎉
