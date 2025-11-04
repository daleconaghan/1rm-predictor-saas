import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from werkzeug.security import generate_password_hash

from app import (
    app,
    db,
    OneRMCalculator,
    RecommendationEngine,
    MLInsightsEngine,
    User,
    OneRMCalculation,
    Workout,
)


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{self.db_path}"
        self.app_context = app.app_context()
        self.app_context.push()
        db.drop_all()
        db.create_all()
        self.client = app.test_client()
        self.cli_runner = app.test_cli_runner()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def create_user(self, username='testuser', password='password', **kwargs):
        user = User(
            username=username,
            email=f"{username}@example.com",
            password_hash=generate_password_hash(password),
            email_verified=True,
            **kwargs,
        )
        db.session.add(user)
        db.session.commit()
        return user

    def login(self, username='testuser', password='password'):
        return self.client.post(
            '/login',
            data={'username': username, 'password': password},
            follow_redirects=True,
        )

    def test_one_rm_calculator_output(self):
        formulas = OneRMCalculator.calculate_all_formulas(200, 5)
        self.assertAlmostEqual(formulas['epley'], 233.3, places=1)
        self.assertIn('mayhew', formulas)
        average = OneRMCalculator.get_average_1rm(200, 5)
        self.assertAlmostEqual(average, 231.7, places=1)

    def test_recommendation_strength_level(self):
        level = RecommendationEngine.get_strength_level(200, 'bench_press', 200)
        self.assertEqual(level, 'Novice')

    def test_api_calculate_enforces_quota(self):
        user = self.create_user(
            username='overlimit', calculations_used_this_month=10
        )
        with self.client:
            self.login(username=user.username)
            response = self.client.post(
                '/api/calculate',
                json={'exercise': 'bench_press', 'weight': 200, 'reps': 5},
            )
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('Monthly limit reached', data['error'])

    def test_api_calculate_records_attempt(self):
        user = self.create_user(username='apiuser')
        with self.client:
            self.login(username=user.username)
            response = self.client.post(
                '/api/calculate',
                json={
                    'exercise': 'bench_press',
                    'weight': 100,
                    'reps': 5,
                    'weight_unit': 'kg',
                    'bodyweight': 80,
                },
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['weight_unit'], 'kg')
        self.assertGreater(len(payload['recommendations']), 0)

        calculation = OneRMCalculation.query.filter_by(user_id=user.id).first()
        self.assertIsNotNone(calculation)
        self.assertEqual(calculation.weight_unit, 'kg')
        refreshed_user = db.session.get(User, user.id)
        self.assertEqual(refreshed_user.calculations_used_this_month, 1)

    def test_cli_commands_execute(self):
        init_result = self.cli_runner.invoke(args=['init-db'])
        self.assertEqual(init_result.exit_code, 0)
        self.assertIn('Database tables initialized.', init_result.output)

        migrate_result = self.cli_runner.invoke(args=['migrate-db'])
        self.assertEqual(migrate_result.exit_code, 0)
        self.assertIn('Skipping migrate-db', migrate_result.output)

        force_result = self.cli_runner.invoke(
            args=['force-migrate'], input='y\n'
        )
        self.assertEqual(force_result.exit_code, 0)
        self.assertIn('force migration complete', force_result.output)

        safe_result = self.cli_runner.invoke(args=['safe-migrate'])
        self.assertEqual(safe_result.exit_code, 0)
        self.assertIn('Safe migration complete', safe_result.output)

    def test_cli_fix_naive_datetimes(self):
        user = self.create_user(username='naiveuser')
        calculation = OneRMCalculation(
            user_id=user.id,
            exercise='bench_press',
            weight=200,
            reps=5,
            calculated_1rm=250,
            formula_used='average',
            weight_unit='lbs',
        )
        db.session.add(calculation)
        db.session.commit()

        user.created_at = datetime(2024, 1, 1, 10, 0, 0)
        user.last_reset_date = datetime(2024, 1, 1, 10, 0, 0)
        user.subscription_expires = datetime(2024, 2, 1, 10, 0, 0)
        calculation.created_at = datetime(2024, 1, 2, 12, 0, 0)
        db.session.commit()

        result = self.cli_runner.invoke(args=['fix-naive-datetimes'])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('Skipping fix-naive-datetimes', result.output)

    def test_ml_insights_requires_data(self):
        """Test that ML insights redirects when insufficient data"""
        user = self.create_user(username='newuser')
        with self.client:
            self.login(username=user.username)
            response = self.client.get('/ml-insights', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        # Should redirect to calculate page with a flash message

    def test_ml_insights_progress_velocity(self):
        """Test progress velocity calculation"""
        user = self.create_user()
        # Create calculations over time
        calcs = []
        for i in range(5):
            calc = OneRMCalculation(
                user_id=user.id,
                exercise='bench_press',
                weight=200 + i * 10,
                reps=5,
                calculated_1rm=220 + i * 10,
                formula_used='average',
                weight_unit='lbs',
                created_at=datetime.now(UTC).replace(hour=0, minute=0, second=0) - timedelta(days=30 * (4 - i))
            )
            calcs.append(calc)
            db.session.add(calc)
        db.session.commit()

        velocity = MLInsightsEngine.calculate_progress_velocity(calcs, 'bench_press')
        self.assertIsNotNone(velocity)
        self.assertGreater(velocity['velocity_per_week'], 0)
        self.assertEqual(velocity['first_1rm'], 220)
        self.assertEqual(velocity['latest_1rm'], 260)

    def test_ml_insights_predict_future_1rm(self):
        """Test future 1RM prediction"""
        user = self.create_user()
        # Create upward trending calculations
        calcs = []
        for i in range(5):
            calc = OneRMCalculation(
                user_id=user.id,
                exercise='squat',
                weight=300 + i * 20,
                reps=5,
                calculated_1rm=350 + i * 20,
                formula_used='average',
                weight_unit='lbs',
                created_at=datetime.now(UTC) - timedelta(days=20 * (4 - i))
            )
            calcs.append(calc)
            db.session.add(calc)
        db.session.commit()

        prediction = MLInsightsEngine.predict_future_1rm(calcs, 'squat', days_ahead=30)
        self.assertIsNotNone(prediction)
        self.assertGreaterEqual(prediction['predicted_1rm'], prediction['current_1rm'])
        self.assertIn('confidence', prediction)

    def test_ml_insights_detect_plateau(self):
        """Test plateau detection"""
        user = self.create_user()
        # Create plateau scenario (no progress in recent period)
        calcs = []
        for i in range(5):
            calc = OneRMCalculation(
                user_id=user.id,
                exercise='deadlift',
                weight=400,
                reps=5,
                calculated_1rm=450,  # Same 1RM (plateau)
                formula_used='average',
                weight_unit='lbs',
                created_at=datetime.now(UTC) - timedelta(days=7 * (4 - i))
            )
            calcs.append(calc)
            db.session.add(calc)
        db.session.commit()

        plateau = MLInsightsEngine.detect_plateau(calcs, 'deadlift', plateau_days=30)
        self.assertIsNotNone(plateau)
        self.assertTrue(plateau['is_plateau'])
        self.assertLess(plateau['improvement_pct'], 2.0)

    def test_ml_insights_strength_balance(self):
        """Test strength balance analysis"""
        user = self.create_user()
        # Create calculations for multiple exercises
        exercises_data = [
            ('bench_press', 200),
            ('squat', 300),
            ('deadlift', 350),
            ('overhead_press', 150)
        ]

        calcs = []
        for exercise, rm in exercises_data:
            calc = OneRMCalculation(
                user_id=user.id,
                exercise=exercise,
                weight=rm * 0.8,
                reps=5,
                calculated_1rm=rm,
                formula_used='average',
                weight_unit='lbs'
            )
            calcs.append(calc)
            db.session.add(calc)
        db.session.commit()

        balance = MLInsightsEngine.analyze_strength_balance(calcs)
        self.assertIsNotNone(balance)
        self.assertIn('exercises', balance)
        self.assertIn('balance', balance)
        self.assertEqual(len(balance['exercises']), 4)

    def test_ml_insights_volume_trends(self):
        """Test volume trends analysis"""
        user = self.create_user()
        # Create workout logs
        workouts = []
        for i in range(10):
            workout = Workout(
                user_id=user.id,
                exercise='bench_press',
                weight=200,
                reps=5,
                effort=2,
                created_at=datetime.now(UTC) - timedelta(days=i)
            )
            workouts.append(workout)
            db.session.add(workout)
        db.session.commit()

        volume = MLInsightsEngine.analyze_volume_trends(workouts, days=30)
        self.assertIsNotNone(volume)
        self.assertEqual(volume['total_workouts'], 10)
        self.assertGreater(volume['total_volume'], 0)
        self.assertIn('effort_distribution', volume)

    def test_ml_insights_personal_records(self):
        """Test personal records retrieval"""
        user = self.create_user()
        # Create calculations with one PR per exercise
        calcs = []
        calc1 = OneRMCalculation(
            user_id=user.id,
            exercise='bench_press',
            weight=200,
            reps=5,
            calculated_1rm=250,
            formula_used='average',
            weight_unit='lbs'
        )
        calc2 = OneRMCalculation(
            user_id=user.id,
            exercise='bench_press',
            weight=225,
            reps=5,
            calculated_1rm=275,  # PR
            formula_used='average',
            weight_unit='lbs',
            created_at=datetime.now(UTC) - timedelta(days=7)
        )
        calcs.extend([calc1, calc2])
        db.session.add_all(calcs)
        db.session.commit()

        prs = MLInsightsEngine.get_personal_records(calcs)
        self.assertIsNotNone(prs)
        self.assertIn('bench_press', prs)
        self.assertEqual(prs['bench_press']['1rm'], 275)

    def test_ml_insights_route_with_data(self):
        """Test ML insights route with sufficient data"""
        user = self.create_user()
        # Create minimum required calculations
        for i in range(3):
            calc = OneRMCalculation(
                user_id=user.id,
                exercise='bench_press',
                weight=200 + i * 10,
                reps=5,
                calculated_1rm=220 + i * 10,
                formula_used='average',
                weight_unit='lbs',
                created_at=datetime.now(UTC) - timedelta(days=30 * (2 - i))
            )
            db.session.add(calc)
        db.session.commit()

        with self.client:
            self.login(username=user.username)
            response = self.client.get('/ml-insights')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'ML Insights Dashboard', response.data)
        self.assertIn(b'Progress Score', response.data)


if __name__ == '__main__':
    unittest.main()
