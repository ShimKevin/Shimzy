from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # For password recovery
    password = db.Column(db.String(200), nullable=False)
    online = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Messages relationship
    messages_sent = db.relationship('Message', 
                                 foreign_keys='Message.sender_id', 
                                 backref='sender', 
                                 lazy='dynamic')
    
    # Explicitly specify foreign keys for calls relationship
    calls_made = db.relationship('Call', 
                                foreign_keys='Call.caller_id',
                                backref='caller', 
                                lazy='dynamic')
    calls_received = db.relationship('Call', 
                                   foreign_keys='Call.receiver_id',
                                   backref='receiver', 
                                   lazy='dynamic')
    
    # Password reset tokens
    reset_tokens = db.relationship('PasswordResetToken', 
                                 backref='user', 
                                 lazy='dynamic',
                                 cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def generate_reset_token(self, expires_in=3600):
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        token = PasswordResetToken(
            user_id=self.id,
            token=secrets.token_urlsafe(32),
            expires_at=expires_at
        )
        db.session.add(token)
        db.session.commit()
        return token.token

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    room = db.Column(db.String(80), nullable=False, default='general')
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_media = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=True)
    
    # For media messages
    media_url = db.Column(db.String(255))
    media_type = db.Column(db.String(50))  # 'image', 'video', 'audio', etc.
    thumbnail_url = db.Column(db.String(255))

class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    call_type = db.Column(db.String(10))  # 'audio' or 'video'
    duration = db.Column(db.Integer)  # Duration in seconds
    is_encrypted = db.Column(db.Boolean, default=True)
    call_status = db.Column(db.String(20), default='completed')  # 'completed', 'missed', 'rejected'
    
    # For encrypted calls
    encryption_key = db.Column(db.String(255))

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    def is_valid(self):
        return datetime.utcnow() < self.expires_at and not self.is_used
    
    def mark_as_used(self):
        self.is_used = True
        db.session.commit()