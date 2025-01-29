from app import db
from flask_user import UserMixin
import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(32), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    last_password_change = db.Column(db.DateTime, nullable=False)
    salt1 = db.Column(db.String(32), nullable=False)
    salt2 = db.Column(db.String(16), nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    totp_secret = db.Column(db.String(10), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    successful = db.Column(db.Boolean, nullable=False)
    
class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(300), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
