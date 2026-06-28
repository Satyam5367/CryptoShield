from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User, AuditLog
from datetime import datetime

auth_bp = Blueprint('auth', __name__)


def log_action(user_id, action, resource, ip, status, details=None):
    log = AuditLog(
        user_id=user_id, action=action, resource=resource,
        ip_address=ip, status=status,
        details=details, timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    required = ['username', 'email', 'password']
    for field in required:
        if not data or field not in data or not str(data[field]).strip():
            return jsonify({'error': f'{field} is required'}), 400

    username = str(data['username']).strip()
    email    = str(data['email']).strip().lower()
    password = str(data['password'])

    if len(username) < 3 or len(username) > 80:
        return jsonify({'error': 'Username must be 3-80 characters'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    log_action(user.id, 'REGISTER', '/auth/register', request.remote_addr, 'success')
    return jsonify({'message': 'Registered successfully'}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400

    username = str(data['username']).strip()
    password = str(data['password'])
    user     = User.query.filter_by(username=username).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        log_action(None, 'LOGIN_FAILED', '/auth/login', request.remote_addr, 'failure',
                   f'Failed attempt: {username}')
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(
        identity=str(user.id),
        additional_claims={'username': user.username}
    )
    log_action(user.id, 'LOGIN', '/auth/login', request.remote_addr, 'success')
    return jsonify({'access_token': token, 'user': user.to_dict()}), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict()), 200
