from app import dynamodb
import bcrypt
from datetime import datetime

TABLE_NAME = "buspass_users"

class UserModel:

    @staticmethod
    def get_table():
        return dynamodb.Table(TABLE_NAME)

    @classmethod
    def create_user(cls, name, email, password, phone):
        table = cls.get_table()
        existing = table.get_item(Key={"email": email}).get("Item")
        if existing:
            return None, "Email already registered"
        hashed = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        user = {
            "email":      email,
            "name":       name,
            "password":   hashed,
            "phone":      phone,
            "created_at": datetime.utcnow().isoformat(),
            "is_active":  True
        }
        table.put_item(Item=user)
        return email, None

    @classmethod
    def find_by_email(cls, email):
        table = cls.get_table()
        response = table.get_item(Key={"email": email})
        return response.get("Item")

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )