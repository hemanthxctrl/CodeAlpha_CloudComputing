import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret')
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/buspassdb')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'fallback-jwt-secret')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    QR_CODE_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'images', 'qr_codes')