from flask import Flask, render_template
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from .config import Config
import boto3
import os

jwt = JWTManager()
dynamodb = None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)
    jwt.init_app(app)
    global dynamodb
    dynamodb = boto3.resource(
        "dynamodb",
        region_name=app.config["AWS_REGION"],
        aws_access_key_id=app.config["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=app.config["AWS_SECRET_ACCESS_KEY"]
    )
    os.makedirs(app.config["QR_CODE_FOLDER"], exist_ok=True)
    from .routes.auth import auth_bp
    from .routes.booking import booking_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(booking_bp, url_prefix="/api/booking")

    @app.route("/")
    def index():
        return render_template("login.html")

    @app.route("/register")
    def register_page():
        return render_template("register.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/book")
    def book_page():
        return render_template("book_pass.html")

    @app.route("/view-pass")
    def view_pass_page():
        return render_template("view_pass.html")

    return app