from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from pymongo import MongoClient
from .config import Config
import os

jwt = JWTManager()
mongo_client = None
db = None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)
    jwt.init_app(app)

    global mongo_client, db
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db = mongo_client.get_database()

    # Create QR codes folder
    qr_folder = app.config['QR_CODE_FOLDER']
    os.makedirs(qr_folder, exist_ok=True)

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.booking import booking_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(booking_bp, url_prefix='/api/booking')

    # Serve frontend
    from flask import render_template
    @app.route('/')
    def index():
        return render_template('login.html')

    @app.route('/register')
    def register_page():
        return render_template('register.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/book')
    def book_page():
        return render_template('book_pass.html')

    @app.route('/view-pass')
    def view_pass_page():
        return render_template('view_pass.html')

    return app