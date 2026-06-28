from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import User, EncryptedFile, AuditLog
from app.crypto_engine import (
    encrypt_and_sign, decrypt_and_verify,
    load_private_key, load_public_key
)
from datetime import datetime
import base64

files_bp = Blueprint('files', __name__)

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'csv', 'json', 'zip'
}


def log_action(user_id, action, resource, ip, status, details=None):
    log = AuditLog(
        user_id=user_id, action=action, resource=resource,
        ip_address=ip, status=status,
        details=details, timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@files_bp.route('/encrypt-upload', methods=['POST'])
@jwt_required()
def encrypt_and_upload():
    """
    Client sends:
      - file: raw file bytes (multipart)
      - recipient_id: int
      - sender_private_key_pem: sender's RSA private key (PEM string) for signing

    Server:
      1. Loads recipient's public key from DB
      2. Encrypts file with AES-256-GCM
      3. Signs ciphertext with sender's private key (RSA-PSS)
      4. Wraps AES key with recipient's RSA public key (OAEP)
      5. Stores the encrypted bundle in DB
    """
    user_id = int(get_jwt_identity())

    if 'file' not in request.files:
        return jsonify({'error': 'file is required'}), 400

    file = request.files['file']
    recipient_id = request.form.get('recipient_id')
    sender_private_key_pem = request.form.get('sender_private_key_pem')

    if not recipient_id or not sender_private_key_pem:
        return jsonify({'error': 'recipient_id and sender_private_key_pem are required'}), 400

    if not file.filename or not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    recipient_id = int(recipient_id)
    recipient = User.query.get(recipient_id)
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    if not recipient.public_key_pem:
        return jsonify({'error': 'Recipient has not uploaded a public key'}), 400

    try:
        sender_private_key   = load_private_key(sender_private_key_pem.encode())
        recipient_public_key = load_public_key(recipient.public_key_pem.encode())
    except Exception:
        return jsonify({'error': 'Invalid private key PEM'}), 400

    plaintext = file.read()
    file_size = len(plaintext)

    try:
        bundle = encrypt_and_sign(plaintext, recipient_public_key, sender_private_key)
    except Exception as e:
        log_action(user_id, 'ENCRYPT_UPLOAD', '/files/encrypt-upload',
                   request.remote_addr, 'failure', str(e))
        return jsonify({'error': 'Encryption failed'}), 500

    encrypted_file = EncryptedFile(
        sender_id=user_id,
        recipient_id=recipient_id,
        filename=file.filename,
        bundle=bundle,
        file_size=file_size
    )
    db.session.add(encrypted_file)
    db.session.commit()

    log_action(user_id, 'ENCRYPT_UPLOAD', '/files/encrypt-upload',
               request.remote_addr, 'success',
               f'File: {file.filename}, Recipient: {recipient_id}, Size: {file_size}B')

    return jsonify({
        'message':   'File encrypted and uploaded successfully',
        'file_id':   encrypted_file.id,
        'filename':  encrypted_file.filename,
        'file_size': file_size
    }), 201


@files_bp.route('/inbox', methods=['GET'])
@jwt_required()
def inbox():
    """List all encrypted files sent to the current user."""
    user_id = int(get_jwt_identity())
    files = EncryptedFile.query.filter_by(recipient_id=user_id).order_by(
        EncryptedFile.uploaded_at.desc()
    ).all()
    return jsonify([f.to_dict() for f in files]), 200


@files_bp.route('/sent', methods=['GET'])
@jwt_required()
def sent():
    """List all files the current user has sent."""
    user_id = int(get_jwt_identity())
    files = EncryptedFile.query.filter_by(sender_id=user_id).order_by(
        EncryptedFile.uploaded_at.desc()
    ).all()
    return jsonify([f.to_dict() for f in files]), 200


@files_bp.route('/decrypt/<int:file_id>', methods=['POST'])
@jwt_required()
def decrypt_file(file_id):
    """
    Client sends:
      - recipient_private_key_pem: recipient's RSA private key for decryption
      - sender_public_key_pem: sender's RSA public key for signature verification

    Server:
      1. Verifies the requester is the intended recipient
      2. Decrypts the AES key using recipient's RSA private key
      3. Verifies digital signature using sender's public key
      4. Decrypts file with AES-256-GCM
      5. Returns plaintext as base64
    """
    user_id = int(get_jwt_identity())

    encrypted_file = EncryptedFile.query.get_or_404(file_id)

    if encrypted_file.recipient_id != user_id:
        log_action(user_id, 'DECRYPT_ATTEMPT', f'/files/decrypt/{file_id}',
                   request.remote_addr, 'failure', 'Unauthorised access attempt')
        return jsonify({'error': 'Access denied — you are not the intended recipient'}), 403

    data = request.get_json()
    if not data or 'recipient_private_key_pem' not in data or 'sender_public_key_pem' not in data:
        return jsonify({'error': 'recipient_private_key_pem and sender_public_key_pem are required'}), 400

    try:
        recipient_private_key = load_private_key(data['recipient_private_key_pem'].encode())
        sender_public_key     = load_public_key(data['sender_public_key_pem'].encode())
    except Exception:
        return jsonify({'error': 'Invalid key PEM format'}), 400

    try:
        plaintext = decrypt_and_verify(
            encrypted_file.bundle,
            recipient_private_key,
            sender_public_key
        )
    except ValueError as e:
        log_action(user_id, 'DECRYPT_TAMPER', f'/files/decrypt/{file_id}',
                   request.remote_addr, 'failure', str(e))
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        log_action(user_id, 'DECRYPT_FAILED', f'/files/decrypt/{file_id}',
                   request.remote_addr, 'failure', str(e))
        return jsonify({'error': 'Decryption failed — wrong key or corrupted data'}), 400

    encrypted_file.downloaded    = True
    encrypted_file.downloaded_at = datetime.utcnow()
    db.session.commit()

    log_action(user_id, 'DECRYPT_SUCCESS', f'/files/decrypt/{file_id}',
               request.remote_addr, 'success', f'File: {encrypted_file.filename}')

    return jsonify({
        'filename':  encrypted_file.filename,
        'plaintext': base64.b64encode(plaintext).decode(),
        'message':   'Signature verified. File integrity confirmed.'
    }), 200


@files_bp.route('/verify/<int:file_id>', methods=['POST'])
@jwt_required()
def verify_only(file_id):
    """
    Verify the digital signature of an encrypted file without decrypting.
    Useful for integrity checks without exposing plaintext.
    """
    user_id = int(get_jwt_identity())
    encrypted_file = EncryptedFile.query.get_or_404(file_id)

    if encrypted_file.recipient_id != user_id:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    if not data or 'sender_public_key_pem' not in data:
        return jsonify({'error': 'sender_public_key_pem is required'}), 400

    try:
        from app.crypto_engine import verify_signature, load_public_key
        import json
        import base64 as b64

        sender_public_key = load_public_key(data['sender_public_key_pem'].encode())
        bundle = json.loads(b64.b64decode(encrypted_file.bundle).decode())
        ciphertext_bytes = b64.b64decode(bundle['ciphertext'])
        valid = verify_signature(ciphertext_bytes, bundle['signature'], sender_public_key)

    except Exception as e:
        return jsonify({'error': f'Verification error: {str(e)}'}), 400

    log_action(user_id, 'VERIFY_SIGNATURE', f'/files/verify/{file_id}',
               request.remote_addr, 'success' if valid else 'failure',
               f'Signature valid: {valid}')

    return jsonify({
        'file_id':          file_id,
        'filename':         encrypted_file.filename,
        'signature_valid':  valid,
        'message':          'Signature valid — file integrity confirmed.' if valid
                            else 'Signature INVALID — file may have been tampered with.'
    }), 200
