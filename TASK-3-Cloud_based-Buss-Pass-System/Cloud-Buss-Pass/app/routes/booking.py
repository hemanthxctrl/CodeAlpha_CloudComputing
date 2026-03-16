from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.booking import BookingModel

booking_bp = Blueprint('booking', __name__)

@booking_bp.route('/book', methods=['POST'])
@jwt_required()
def book_pass():
    user_id = get_jwt_identity()
    data = request.get_json()

    pass_type = data.get('pass_type', '').lower()
    route = data.get('route', '').strip()
    passenger_name = data.get('passenger_name', '').strip()

    if not all([pass_type, route, passenger_name]):
        return jsonify({'error': 'All fields required'}), 400

    booking, error = BookingModel.create_booking(user_id, pass_type, route, passenger_name)
    if error:
        return jsonify({'error': error}), 400

    return jsonify({
        'message': 'Pass booked successfully',
        'pass_id': booking['pass_id'],
        'pass_type': booking['pass_type'],
        'route': booking['route'],
        'price': booking['price'],
        'expiry_date': booking['expiry_date'].strftime('%Y-%m-%d'),
        'qr_code': booking['qr_code']
    }), 201


@booking_bp.route('/my-passes', methods=['GET'])
@jwt_required()
def my_passes():
    user_id = get_jwt_identity()
    bookings = BookingModel.get_user_bookings(user_id)
    return jsonify({'passes': bookings}), 200


@booking_bp.route('/prices', methods=['GET'])
def get_prices():
    from app.models.booking import PASS_PRICES
    return jsonify({'prices': PASS_PRICES}), 200