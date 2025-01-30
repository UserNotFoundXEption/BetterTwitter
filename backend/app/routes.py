from flask import Blueprint, jsonify, request, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from time import time, sleep
from collections import defaultdict
from app import db
from app.models import User
from app.models import Message
from app.models import LoginAttempt
from app.models import EmailVerification
import jwt
import datetime
import os
import rsa
from app import utils
import pyotp
import qrcode
import io
import base64
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from itsdangerous import URLSafeTimedSerializer
import datetime

SECRET_KEY = 'L9p$3#k!zF*Qxr8@WmD%vGH4YtCq&7J'
api = Blueprint('api', __name__)
limiter = Limiter(get_remote_address, app=None)
serializer = URLSafeTimedSerializer(SECRET_KEY)

users = {}
login_attempts_list = defaultdict(lambda: {"count": 0, "last_attempt": 0, "block_until": 0})
password_reset_salt = {}

LOCK_TIME = 3600
MAX_ATTEMPTS = 5
DELAY_AFTER_LOGIN = 1

@api.route('/')
def home():
    return render_template('index.html')


@api.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = utils.sanitize_content(data.get('username'))
    email = utils.sanitize_content(data.get('email'))
    password = utils.sanitize_content(data.get('password'))
    
    if len(username) > 32:
        return jsonify({'error': 'Username too long. (max 32 characters)'}), 400
    
    if len(email) > 32:
        return jsonify({'error': 'Email too long. (max 32 characters)'}), 400

    password_verification_message = utils.verify_password(password)
    if password_verification_message != "ok":
        return jsonify({'error': password_verification_message}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists.'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email is already taken.'}), 400
    
    (public_key, private_key) = rsa.newkeys(2048)
    private_key_pem = private_key.save_pkcs1().decode()
    public_key_pem = public_key.save_pkcs1().decode()
    
    salt1, salt2, hash2 = utils.hash_password_new(password)
    
    secret = pyotp.random_base32()
    totp_secret = pyotp.TOTP(secret)
    uri = totp_secret.provisioning_uri(name=username, issuer_name="BetterTwitter")
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    users[username] = {
        'email': email,
        'hash2': hash2,
        'salt1': salt1,
        'salt2': salt2,
        'private_key': private_key_pem,
        'public_key': public_key_pem,
        'secret' : secret
    }
    return jsonify({'message': 'Scan the QR code with your 2FA app.', 'qr_code': qr_base64})


@api.route('/register/verify-totp', methods=['POST'])
def register_verify_totp():
    data = request.get_json()
    username = utils.sanitize_content(data['username'])
    totp_code = utils.sanitize_content(data['totp_code'])

    user = users.get(username)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    email = user['email']
    hash2 = user['hash2']
    salt1 = user['salt1']
    salt2 = user['salt2']
    private_key = user['private_key']
    public_key = user['public_key']
    secret = user['secret']
    totp_secret = pyotp.TOTP(secret)
    if not totp_secret.verify(totp_code):
        return jsonify({'error': 'Invalid code'}), 401
    
    user = User(username=username, email=email, email_verified=False, password=hash2, last_password_change=datetime.datetime.utcnow(), salt1=salt1, salt2=salt2, private_key=private_key, public_key=public_key, totp_secret=secret)
    db.session.add(user)
    
    email_salt = os.urandom(32)
    email_token = serializer.dumps(user.email, salt=email_salt)
    email_verification = EmailVerification(token=email_token, salt=email_salt)
    db.session.add(email_verification)
    
    db.session.commit()
    
    confirmation_link = f'/confirm-email/{email_token}'
    
    return jsonify({'message': f'Verification successful, registration complete. Email confirmation link that would normally be sent through email:', 'link': confirmation_link})


@api.route('/confirm-email/<token>', methods=['POST'])
def confirm_email(token):
    try:
        salt = EmailVerification.query.filter_by(token=token).first().salt 
        email = serializer.loads(token, salt=salt)
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Invalid link.'}), 404
        if not user.email_verified:
            user.email_verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully.'}), 200
        else:
            return jsonify({'message': 'Email has already been verified.'}), 403
    except:
      pass
    return jsonify({'error': 'Invalid link.'}), 404


@api.route('/login', methods=['POST'])
def login():
    sleep(DELAY_AFTER_LOGIN)

    data = request.get_json()
    username = utils.sanitize_content(data.get('username'))
    password = utils.sanitize_content(data.get('password'))
    totp_code = utils.sanitize_content(data.get('totpCode'))
    
    ip = utils.sanitize_content(data.get('ip'))
    current_time = time()
    attempts_data = login_attempts_list[ip]
    
    if current_time < attempts_data["block_until"]:
        time_to_unblock = int((attempts_data["block_until"] - current_time) / 60)
        return jsonify({'error': f'Too many failed attempts. Try again in {time_to_unblock} minutes.'}), 403
    
    
    user = User.query.filter_by(username=username).first()
    successful = False

    if user:
        salt1 = user.salt1
        salt2 = user.salt2
        hash2 = utils.hash_password(password, salt1, salt2)
        if hash2 == user.password:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(totp_code):
                token = jwt.encode(
                    {'user_id': user.id,
                    'iat': datetime.datetime.utcnow(),
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                    SECRET_KEY,
                    algorithm='HS256'
                )
                login_attempt = LoginAttempt(user_id=user.id, ip=ip, successful=True)
                db.session.add(login_attempt)
                db.session.commit()
                login_attempts_list.pop(ip, None)
                return jsonify({'token': token})
        login_attempt = LoginAttempt(user_id=user.id, ip=ip, successful=False)
        db.session.add(login_attempt)
        db.session.commit()

    attempts_data["count"] += 1
    if attempts_data["count"] >= MAX_ATTEMPTS:
        attempts_data["block_until"] = current_time + LOCK_TIME
        return jsonify({'error': 'Too many failed attempts. You are blocked for 1 hour.'}), 403
    login_attempts_list[ip] = attempts_data

    return jsonify({'error': 'Invalid credentials.'}), 401


@api.route('/login-attempts', methods=['GET'])
def login_attempts():
    try:
        decoded = utils.validate_token(SECRET_KEY, request)
        user_id = decoded['user_id']
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found.'}), 404

        login_attempts_list = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.time.desc()).all()
        attempts_data = [
            {
                'time': attempt.time,
                'ip': attempt.ip,
                'successful': attempt.successful
            }
            for attempt in login_attempts_list
        ]
        return jsonify({'login_attempts': attempts_data}), 200
    except ExpiredSignatureError:
        return jsonify({'error': 'Session expired. Try to log in again.'}), 401
    except InvalidTokenError:
        return jsonify({'error': 'You don\'t have access to this place. Log in first.'}), 401


@api.route('/messages', methods=['GET'])
def messages():
    messages = Message.query.all()
    return jsonify([{'username': msg.username, 'content': msg.content, 'id': msg.id} for msg in messages])


@api.route('/messages/send', methods=['POST'])
def messages_send():
    data = request.get_json()
    try:
        decoded = utils.validate_token(SECRET_KEY, request)
        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'error': 'User not found.'}), 404
         
        content = utils.sanitize_content(data.get('content'))
        if len(content) > 500:
            return jsonify({'error': 'Message too long. (max 500 characters)'}), 400
        signature = utils.sign_message(content, user.private_key)
        image_link = utils.extract_image_url(content)
        if image_link is not None:
            image_is_valid = utils.validate_image_size(image_link)
            if not image_is_valid[0]:
                print(image_is_valid)
                return jsonify({'error': 'Image too big. (max 1920x1080)'}), 400
        
        message = Message(username=user.username, content=content, signature=signature)
        db.session.add(message)
        db.session.commit()

        return jsonify({'username': user.username, 'content': content, 'signature': signature})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Session expired. Try to log in again.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Not logged in. Log in first.'}), 401


@api.route('/messages/verify/<int:message_id>', methods=['GET'])
def messages_verify(message_id):
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'error': 'Message not found.'}), 404

    user = User.query.filter_by(username=message.username).first()
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    public_key = rsa.PublicKey.load_pkcs1(user.public_key.encode())

    try:
        rsa.verify(message.content.encode(), bytes.fromhex(message.signature), public_key)
        verification_status = "Signature is valid"
    except rsa.VerificationError:
        verification_status = "Signature is invalid"

    return jsonify({
        'content': message.content,
        'signature': message.signature,
        'public_key': user.public_key,
        'verification_status': verification_status
    })


@api.route('/validate_token', methods=['GET'])
def validate_token():
    try:
        decoded = utils.validate_token(SECRET_KEY, request)
        return jsonify({'valid': True, 'user_id': decoded['user_id']}), 200
    except ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Session expired. Try to log in again.'}), 401
    except InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Not logged in. Log in first.'}), 401


@api.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = utils.sanitize_content(data.get('email'))

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email not found.'}), 404
    if not user.email_verified:
        return jsonify({'error': 'Can\'t send password reset request to unverified email.'}), 403

    salt = os.urandom(32)
    token = serializer.dumps(user.email, salt=salt)
    password_reset_salt[token] = salt
    reset_link = f'/reset-password/{token}'

    return jsonify({'reset_link': reset_link}), 200


@api.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        salt = password_reset_salt[token]
        email = serializer.loads(token, salt=salt, max_age=3600)
        data = request.get_json()
        new_password = utils.sanitize_content(data.get('password'))
        
        password_verification_message = utils.verify_password(new_password)
        if password_verification_message != "ok":
            return jsonify({'error': password_verification_message}), 400
        
        user = User.query.filter_by(email=email).first()
        if user:
            salt1, salt2, hash2 = utils.hash_password_new(new_password)
            user.salt1 = salt1
            user.salt2 = salt2
            user.password = hash2
            user.last_password_change = datetime.datetime.utcnow()
            db.session.commit()
            return jsonify({'message': 'Password changed.'}), 200
        else:
            return jsonify({'error': 'User not found.'}), 404
    except Exception as e:
        return jsonify({'error': 'Invalid or expired link.'}), 401


def setup_routes(app):
    app.register_blueprint(api)
    with app.app_context():
        db.create_all()
