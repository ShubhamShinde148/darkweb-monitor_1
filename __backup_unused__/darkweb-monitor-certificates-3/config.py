import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key'
    FIREBASE_CREDENTIALS = os.path.join(os.path.dirname(__file__), 'darkweb-monitor-fee1c-firebase-adminsdk-fbsvc-be2b34d535.json')
    FIREBASE_PROJECT_ID = 'darkweb-monitor-fee1c'
    DEBUG = os.environ.get('DEBUG') == '1'
    # Add any other configuration variables as needed