from flask import Flask
from flask_cors import CORS
from firebase_admin import credentials, initialize_app

def create_app():
    app = Flask(__name__)
    CORS(app)

    # Load configuration from config.py
    app.config.from_object('config')

    # Initialize Firebase Admin SDK
    cred = credentials.Certificate(app.config['FIREBASE_CREDENTIALS'])
    initialize_app(cred)

    # Import and register blueprints
    from .views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app