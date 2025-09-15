import os
import tempfile
import unittest
from datetime import UTC, datetime

from werkzeug.security import generate_password_hash

from app import (
    app,
    db,
    OneRMCalculator,
    RecommendationEngine,
    User,
    OneRMCalculation,
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


if __name__ == '__main__':
    unittest.main()
