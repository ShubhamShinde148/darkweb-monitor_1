import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key'
    FIREBASE_PROJECT_ID = os.environ.get('FIREBASE_PROJECT_ID')
    FIREBASE_PRIVATE_KEY_ID = os.environ.get('FIREBASE_PRIVATE_KEY_ID')
    FIREBASE_PRIVATE_KEY = os.environ.get('FIREBASE_PRIVATE_KEY').replace('\\n', '\n')
    FIREBASE_CLIENT_EMAIL = os.environ.get('FIREBASE_CLIENT_EMAIL')
    FIREBASE_CLIENT_ID = os.environ.get('FIREBASE_CLIENT_ID')
    FIREBASE_AUTH_URI = os.environ.get('FIREBASE_AUTH_URI')
    FIREBASE_TOKEN_URI = os.environ.get('FIREBASE_TOKEN_URI')
    FIREBASE_AUTH_PROVIDER_CERT_URL = os.environ.get('FIREBASE_AUTH_PROVIDER_CERT_URL')
    FIREBASE_CLIENT_CERT_URL = os.environ.get('FIREBASE_CLIENT_CERT_URL')
    
    # Additional configuration settings can be added here as needed
    DEBUG = os.environ.get('DEBUG', 'False') == 'True'