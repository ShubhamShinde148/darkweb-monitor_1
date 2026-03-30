from flask import Flask
from firebase_admin import credentials, initialize_app

def create_app():
    app = Flask(__name__)
    
    # Load configuration from config.py
    app.config.from_object('config')

    # Initialize Firebase
    cred = credentials.Certificate(app.config['FIREBASE_CREDENTIALS'])
    initialize_app(cred)

    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .admin.dashboard import admin as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')

    return app