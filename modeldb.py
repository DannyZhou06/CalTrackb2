# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pyotp

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    injuries = db.Column(db.Text, nullable=True)
    objective = db.Column(db.Text, nullable=True)
    intensity = db.Column(db.String(50), nullable=True)
    
    # --- 2FA Fields ---
    otp_secret = db.Column(db.String(16))
    is_otp_enabled = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    trainer_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_members = db.relationship('User', backref=db.backref('trainer', remote_side=[id]), lazy='dynamic', foreign_keys='User.trainer_id')
    attendance_records = db.relationship('Attendance', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    body_measurements = db.relationship('BodyMeasurement', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            self.otp_secret = pyotp.random_base32()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def age(self):
        if self.date_of_birth:
            today = datetime.utcnow().date()
            return today.year - self.date_of_birth.year - ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))
        return None

    def get_totp_uri(self):
        return f'otpauth://totp/GymTracker:{self.username}?secret={self.otp_secret}&issuer=GymTracker'

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    check_in_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class BodyMeasurement(db.Model):
    __tablename__ = 'body_measurements'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_date = db.Column(db.Date, nullable=False, default=datetime.utcnow().date)
    weight_kg = db.Column(db.Float, nullable=True)
    height_cm = db.Column(db.Float, nullable=True)
    body_fat_percentage = db.Column(db.Float, nullable=True)
    muscle_mass_kg = db.Column(db.Float, nullable=True)
    bone_mass_kg = db.Column(db.Float, nullable=True)
    visceral_fat_rating = db.Column(db.Integer, nullable=True)

    @property
    def bmi(self):
        if self.weight_kg and self.height_cm:
            return round(self.weight_kg / ((self.height_cm / 100) ** 2), 1)
        return None
