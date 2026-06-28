from app import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # User's RSA public key stored as PEM (private key stays client-side)
    public_key_pem = db.Column(db.Text, nullable=True)

    sent_files     = db.relationship('EncryptedFile', foreign_keys='EncryptedFile.sender_id',   backref='sender',    lazy=True)
    received_files = db.relationship('EncryptedFile', foreign_keys='EncryptedFile.recipient_id', backref='recipient', lazy=True)
    audit_logs     = db.relationship('AuditLog', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'username':   self.username,
            'email':      self.email,
            'has_key':    self.public_key_pem is not None,
            'created_at': self.created_at.isoformat()
        }


class EncryptedFile(db.Model):
    __tablename__ = 'encrypted_files'

    id           = db.Column(db.Integer, primary_key=True)
    sender_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename     = db.Column(db.String(255), nullable=False)
    bundle       = db.Column(db.Text, nullable=False)   # base64 JSON bundle
    file_size    = db.Column(db.Integer, nullable=True)
    uploaded_at  = db.Column(db.DateTime, default=datetime.utcnow)
    downloaded   = db.Column(db.Boolean, default=False)
    downloaded_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id':            self.id,
            'sender_id':     self.sender_id,
            'recipient_id':  self.recipient_id,
            'filename':      self.filename,
            'file_size':     self.file_size,
            'uploaded_at':   self.uploaded_at.isoformat(),
            'downloaded':    self.downloaded,
            'downloaded_at': self.downloaded_at.isoformat() if self.downloaded_at else None
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    resource   = db.Column(db.String(200), nullable=True)
    ip_address = db.Column(db.String(50),  nullable=True)
    status     = db.Column(db.String(20),  nullable=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    details    = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'user_id':    self.user_id,
            'action':     self.action,
            'resource':   self.resource,
            'ip_address': self.ip_address,
            'status':     self.status,
            'timestamp':  self.timestamp.isoformat(),
            'details':    self.details
        }
