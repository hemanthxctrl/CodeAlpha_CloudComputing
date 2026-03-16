from app import db
import bcrypt
from datetime import datetime

class UserModel:
    collection = None

    @classmethod
    def get_collection(cls):
        if cls.collection is None:
            cls.collection = db['users']
        return cls.collection

    @classmethod
    def create_user(cls, name, email, password, phone):
        col = cls.get_collection()
        if col.find_one({'email': email}):
            return None, 'Email already exists'
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {
            'name': name,
            'email': email,
            'password': hashed,
            'phone': phone,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        result = col.insert_one(user)
        return str(result.inserted_id), None

    @classmethod
    def find_by_email(cls, email):
        return cls.get_collection().find_one({'email': email})

    @classmethod
    def verify_password(cls, plain_password, hashed_password):
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)