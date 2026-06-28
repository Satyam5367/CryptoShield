from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import User, AuditLog
from datetime import datetime

keys_bp = Blueprint('keys', __name__)


def log_action(user_id, action, resource, ip, status, details=None):
    log = AuditLog(
        user_id=user_id, action=action, resource=resource,
        ip_address=ip, status=status,
        details=details, timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()


@keys_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_public_key():
    """User uploads their RSA public key PEM to the server."""
    user_id = int(get_jwt_identity())
    data = request.get_json()

    if not data or 'public_key_pem' not in data:
        return jsonify({'error': 'public_key_pem is required'}), 400

    pem = str(data['public_key_pem']).strip()

    if not pem.startswith('-----BEGIN PUBLIC KEY-----'):
        return jsonify({'error': 'Invalid PEM format'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.public_key_pem = pem
    db.session.commit()

    log_action(user_id, 'UPLOAD_PUBLIC_KEY', '/keys/upload',
               request.remote_addr, 'success')

    return jsonify({'message': 'Public key uploaded successfully'}), 200


@keys_bp.route('/user/<int:target_user_id>', methods=['GET'])
@jwt_required()
def get_user_public_key(target_user_id):
    """Fetch another user's public key to encrypt a file for them."""
    user = User.query.get(target_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if not user.public_key_pem:
        return jsonify({'error': 'User has not uploaded a public key'}), 404

    return jsonify({
        'user_id':        user.id,
        'username':       user.username,
        'public_key_pem': user.public_key_pem
    }), 200


@keys_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users_with_keys():
    """List all users who have uploaded a public key (so you can send them files)."""
    users = User.query.filter(User.public_key_pem.isnot(None)).all()
    return jsonify([u.to_dict() for u in users]), 200
