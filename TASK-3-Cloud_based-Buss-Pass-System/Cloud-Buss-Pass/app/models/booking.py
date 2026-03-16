from app import db
from datetime import datetime, timedelta
import qrcode
import os
import uuid
from app.config import Config

PASS_PRICES = {
    'daily': 30,
    'weekly': 150,
    'monthly': 500,
    'yearly': 5000
}

PASS_DURATIONS = {
    'daily': 1,
    'weekly': 7,
    'monthly': 30,
    'yearly': 365
}

class BookingModel:
    collection = None

    @classmethod
    def get_collection(cls):
        if cls.collection is None:
            cls.collection = db['bookings']
        return cls.collection

    @classmethod
    def create_booking(cls, user_id, pass_type, route, passenger_name):
        col = cls.get_collection()

        if pass_type not in PASS_PRICES:
            return None, 'Invalid pass type'

        price = PASS_PRICES[pass_type]
        duration = PASS_DURATIONS[pass_type]
        pass_id = str(uuid.uuid4())[:8].upper()
        expiry = datetime.utcnow() + timedelta(days=duration)

        # Generate QR code
        qr_data = f"PASS:{pass_id}|USER:{user_id}|TYPE:{pass_type}|ROUTE:{route}|EXP:{expiry.date()}"
        qr_img = qrcode.make(qr_data)
        qr_filename = f"qr_{pass_id}.png"
        qr_path = os.path.join(Config.QR_CODE_FOLDER, qr_filename)
        qr_img.save(qr_path)

        booking = {
            'pass_id': pass_id,
            'user_id': user_id,
            'passenger_name': passenger_name,
            'pass_type': pass_type,
            'route': route,
            'price': price,
            'booked_at': datetime.utcnow(),
            'expiry_date': expiry,
            'qr_code': qr_filename,
            'is_active': True
        }
        result = col.insert_one(booking)
        return booking, None

    @classmethod
    def get_user_bookings(cls, user_id):
        bookings = list(cls.get_collection().find({'user_id': user_id}))
        for b in bookings:
            b['_id'] = str(b['_id'])
            b['booked_at'] = b['booked_at'].strftime('%Y-%m-%d')
            b['expiry_date'] = b['expiry_date'].strftime('%Y-%m-%d')
        return bookings