import unittest
from unittest.mock import patch
from app import app, User
from werkzeug.security import generate_password_hash

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    @patch('app.get_user_by_id')
    @patch('app.get_user_by_identifier')
    @patch('app.update_last_login')
    def test_login_logout(self, mock_update_last_login, mock_get_user_by_identifier, mock_get_user_by_id):
        # Mock user
        mock_user = User(
            user_id='test-user-id',
            username='testuser',
            email='test@example.com',
            password_hash=generate_password_hash('password')
        )
        mock_get_user_by_identifier.return_value = mock_user
        mock_get_user_by_id.return_value = mock_user

        with self.client as c:
            # Login
            login_res = c.post('/login', data={'identifier': 'testuser', 'password': 'password'}, follow_redirects=True)
            self.assertEqual(login_res.status_code, 200)
            self.assertIn(b'Welcome back, testuser.', login_res.data)
            mock_get_user_by_identifier.assert_called_with('testuser')
            mock_update_last_login.assert_called_with('test-user-id')

            # Logout
            logout_res = c.post('/logout', follow_redirects=True)
            self.assertEqual(logout_res.status_code, 200)
            self.assertIn(b'You have been logged out.', logout_res.data)


    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

if __name__ == '__main__':
    unittest.main()
