from flask import Flask
from flask_session import Session
import pyrebase
from .crypto import AESCipher

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object('config.Config')
    
    # Initialize Firebase
    firebase = pyrebase.initialize_app(app.config['FIREBASE_CONFIG'])
    db = firebase.database()
    auth = firebase.auth()
    storage = firebase.storage()
    
    app.config['FIREBASE_DB'] = db
    app.config['FIREBASE_AUTH'] = auth
    app.config['FIREBASE_STORAGE'] = storage
    
    # Session configuration
    Session(app)
    
    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500
    
    return app
