import unittest
from app import create_app, db
from app.admin.dashboard import get_dashboard_data
from app.admin.performance import get_user_performance

class AdminDashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_dashboard_data(self):
        response = get_dashboard_data()
        self.assertIn('total_certificates', response)
        self.assertIn('recent_certificates', response)
        self.assertIn('verification_logs', response)

    def test_user_performance(self):
        response = get_user_performance()
        self.assertIsInstance(response, list)

if __name__ == '__main__':
    unittest.main()