from app import dynamodb
from datetime import datetime, timedelta
from boto3.dynamodb.conditions import Key
import qrcode
import os
import uuid
from app.config import Config

TABLE_NAME = "buspass_bookings"
PASS_PRICES    = {"daily": 30, "weekly": 150, "monthly": 500, "yearly": 5000}
PASS_DURATIONS = {"daily": 1,  "weekly": 7,   "monthly": 30,  "yearly": 365}

class BookingModel:

    @staticmethod
    def get_table():
        return dynamodb.Table(TABLE_NAME)

    @classmethod
    def create_booking(cls, user_id, pass_type, route, passenger_name):
        if pass_type not in PASS_PRICES:
            return None, "Invalid pass type"
        table    = cls.get_table()
        price    = PASS_PRICES[pass_type]
        duration = PASS_DURATIONS[pass_type]
        pass_id  = str(uuid.uuid4())[:8].upper()
        expiry   = datetime.utcnow() + timedelta(days=duration)
        qr_data  = f"PASS:{pass_id}|USER:{user_id}|TYPE:{pass_type}|ROUTE:{route}|EXP:{expiry.date()}"
        qr_img   = qrcode.make(qr_data)
        qr_file  = f"qr_{pass_id}.png"
        qr_img.save(os.path.join(Config.QR_CODE_FOLDER, qr_file))
        booking = {
            "user_id":        user_id,
            "pass_id":        pass_id,
            "passenger_name": passenger_name,
            "pass_type":      pass_type,
            "route":          route,
            "price":          price,
            "booked_at":      datetime.utcnow().isoformat(),
            "expiry_date":    expiry.strftime("%Y-%m-%d"),
            "qr_code":        qr_file,
            "is_active":      True
        }
        table.put_item(Item=booking)
        return booking, None

    @classmethod
    def get_user_bookings(cls, user_id):
        table    = cls.get_table()
        response = table.query(
            KeyConditionExpression=Key("user_id").eq(user_id)
        )
        bookings = response.get("Items", [])
        for b in bookings:
            b["price"] = int(b["price"])
        return bookings