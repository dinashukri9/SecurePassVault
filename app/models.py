from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    master_password = db.Column(db.String(255), nullable=False)
    session_timeout = db.Column(db.Integer, default=10)

    # Reset password
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    is_reset_locked = db.Column(db.Boolean, default=False)

    # 3 Security questions
    security_question_1 = db.Column(db.String(255), nullable=True)
    security_answer_1 = db.Column(db.String(255), nullable=True)
    security_question_2 = db.Column(db.String(255), nullable=True)
    security_answer_2 = db.Column(db.String(255), nullable=True)
    security_question_3 = db.Column(db.String(255), nullable=True)
    security_answer_3 = db.Column(db.String(255), nullable=True)

    # 2FA
    two_fa_method = db.Column(db.String(20), nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    two_fa_verified = db.Column(db.Boolean, default=False)
    two_fa_temp_code = db.Column(db.String(10), nullable=True)
    two_fa_code_expiry = db.Column(db.DateTime, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    email_2fa_enabled = db.Column(db.Boolean, default=False)

    # Last login
    last_login = db.Column(db.DateTime, nullable=True)

    # Biometric
    biometric_registered = db.Column(db.Boolean, default=False)
    biometric_fingers = db.Column(db.Integer, default=0)  # 0 = none, 1 = one finger, 2 = two fingers

    passwords = db.relationship('Password', backref='user', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(255))
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)


class ActivityLog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action     = db.Column(db.String(50),  nullable=False)
    detail     = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45),  nullable=True)
    status     = db.Column(db.String(10),  nullable=False, default='success')
    timestamp  = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow)