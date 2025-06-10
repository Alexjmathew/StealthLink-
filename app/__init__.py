from flask import Flask
import pyrebase
import json

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize Firebase
    with open(app.config['FIREBASE_CONFIG']) as f:
        firebase_config = json.load(f)
    firebase = pyrebase.initialize_app(firebase_config)
    app.firebase = firebase
    app.db = firebase.database()
    app.auth = firebase.auth()

    # Register blueprints
    from .routes import main
    app.register_blueprint(main)

    return app
