from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from app.models.user import UserModel

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    phone = data.get('phone', '').strip()

    if not all([name, email, password, phone]):
        return jsonify({'error': 'All fields are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if '@' not in email:
        return jsonify({'error': 'Invalid email address'}), 400

    user_id, error = UserModel.create_user(name, email, password, phone)
    if error:
        return jsonify({'error': error}), 409

    token = create_access_token(identity=user_id)
    return jsonify({'message': 'Registered successfully', 'token': token, 'name': name}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    user = UserModel.find_by_email(email)
    if not user or not UserModel.verify_password(password, user['password']):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = create_access_token(identity=str(user['_id']))
    return jsonify({'message': 'Login successful', 'token': token, 'name': user['name']}), 200