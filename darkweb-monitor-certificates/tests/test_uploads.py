import unittest
import os
from flask import Flask
from app.views import configure_routes

class TestUploads(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test_secret_key'
        self.app.config['UPLOAD_FOLDER'] = 'uploads'
        if not os.path.exists(self.app.config['UPLOAD_FOLDER']):
            os.makedirs(self.app.config['UPLOAD_FOLDER'])
        configure_routes(self.app)
        self.client = self.app.test_client()

    def tearDown(self):
        # Clean up created files and directories
        pass

    def test_upload_certificate(self):
        # This is a placeholder for the actual test
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
