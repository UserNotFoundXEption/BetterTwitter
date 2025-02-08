from flask import Blueprint, jsonify, request, render_template
from time import time, sleep
from collections import defaultdict
from app import db
from app.models import User, UserTemp, Message, LoginAttempt, EmailVerification, PasswordChangeTemp
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
from datetime import timedelta

APP_SECRET = utils.get_env_var("APP_SECRET")
SALT_SECRET = utils.get_env_var("SALT_SECRET")
KEY_SECRET = utils.get_env_var("KEY_SECRET")
TOTP_SECRET = utils.get_env_var("TOTP_SECRET")

api = Blueprint('api', __name__)
serializer = URLSafeTimedSerializer(APP_SECRET)

LOCK_TIME = timedelta(seconds=3600)
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
    
    salt = os.urandom(32)
    password_hash = utils.hash_password(password, salt)
    
    secret = pyotp.random_base32()
    totp_secret = pyotp.TOTP(secret)
    uri = totp_secret.provisioning_uri(name=username, issuer_name="BetterTwitter")
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    salt_base64 = base64.b64encode(salt).decode()
    salt_encrypted = utils.aes_encrypt(salt_base64, username, SALT_SECRET)
    private_key_encrypted = utils.aes_encrypt(private_key_pem, username, KEY_SECRET)
    totp_secret_encrypted = utils.aes_encrypt(secret, username, TOTP_SECRET)

    userTemp = UserTemp(username=username, email=email, password_hash=password_hash, salt_encrypted=salt_encrypted, private_key_encrypted=private_key_encrypted, public_key=public_key_pem, totp_secret_encrypted=totp_secret_encrypted)
    db.session.add(userTemp)
    db.session.commit()
    
    return jsonify({'message': 'Scan the QR code with your 2FA app.', 'qr_code': qr_base64})


@api.route('/register/verify-totp', methods=['POST'])
def register_verify_totp():
    data = request.get_json()
    username = utils.sanitize_content(data['username'])
    totp_code = utils.sanitize_content(data['totp_code'])

    userTemp = UserTemp.query.filter_by(username=username).first()
    if not userTemp:
        return jsonify({'error': 'User not found.'}), 404

    totp_secret_encrypted = userTemp.totp_secret_encrypted
    secret = utils.aes_decrypt(totp_secret_encrypted, username, TOTP_SECRET)
    totp_secret = pyotp.TOTP(secret)
    if not totp_secret.verify(totp_code):
        return jsonify({'error': 'Invalid code'}), 401
    
    email = userTemp.email
    password_hash = userTemp.password_hash
    salt_encrypted = userTemp.salt_encrypted
    private_key_encrypted = userTemp.private_key_encrypted
    public_key = userTemp.public_key
    
    user = User(
        username=username, 
        email=email, 
        email_verified=False, 
        password_hash=password_hash, 
        salt_encrypted=salt_encrypted, 
        private_key_encrypted=private_key_encrypted, 
        public_key=public_key, 
        totp_secret_encrypted=totp_secret_encrypted,
        last_password_change=datetime.datetime.utcnow())
    
    email_salt = os.urandom(32)
    email_token = serializer.dumps(user.email, salt=email_salt)
    email_verification = EmailVerification(token=email_token, salt=email_salt)
    
    db.session.add(user)
    db.session.delete(userTemp)
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
    data = request.get_json()
    username = utils.sanitize_content(data.get('username'))
    password = utils.sanitize_content(data.get('password'))
    totp_code = utils.sanitize_content(data.get('totpCode'))
    ip = utils.sanitize_content(data.get('ip'))
    
    user = User.query.filter_by(username=username).first()
    successful = False

    if user:
        failed_logins = user.failed_logins
        last_failed_login = user.last_failed_login
        current_time = datetime.datetime.utcnow()
        if current_time - last_failed_login < timedelta(seconds=1):
            return jsonify({'error': f'Slow down!'}), 403   
        if failed_logins >= 5 and current_time - last_failed_login < LOCK_TIME:
            time_to_unblock = int((last_failed_login + LOCK_TIME - current_time).total_seconds() / 60)
            return jsonify({'error': f'Too many failed attempts. Try again in {time_to_unblock} minutes.'}), 403
        
        salt_base64 = utils.aes_decrypt(user.salt_encrypted, username, SALT_SECRET)
        salt = base64.b64decode(salt_base64)
        password_hash = utils.hash_password(password, salt)
        if password_hash == user.password_hash:
        
            totp_secret = utils.aes_decrypt(user.totp_secret_encrypted, username, TOTP_SECRET)
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
            
                token = jwt.encode(
                    {'user_id': user.id,
                    'iat': datetime.datetime.utcnow(),
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                    APP_SECRET,
                    algorithm='HS256'
                )
                user.failed_logins = 0
                login_attempt = LoginAttempt(user_id=user.id, ip=ip, successful=True)
                db.session.add(login_attempt)
                db.session.commit()
                return jsonify({'token': token})
                
        user.failed_logins = user.failed_logins + 1
        login_attempt = LoginAttempt(user_id=user.id, ip=ip, successful=False)
        db.session.add(login_attempt)
        db.session.commit()
        
    return jsonify({'error': 'Invalid credentials.'}), 401


@api.route('/login-attempts', methods=['GET'])
def login_attempts():
    try:
        decoded = utils.validate_token(APP_SECRET, request)
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
        decoded = utils.validate_token(APP_SECRET, request)
        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'error': 'User not found.'}), 404
         
        content = utils.sanitize_content(data.get('content'))
        if len(content) > 500:
            return jsonify({'error': 'Message too long. (max 500 characters)'}), 400
        private_key = utils.aes_decrypt(user.private_key_encrypted, user.username, KEY_SECRET)
        signature = utils.sign_message(content, private_key)
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
        decoded = utils.validate_token(APP_SECRET, request)
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
    
    salt_base64 = base64.b64encode(salt).decode()
    salt_encrypted = utils.aes_encrypt(salt_base64, user.username, SALT_SECRET)
    passwordChangeTemp = PasswordChangeTemp(
        token=token,
        salt_encrypted=salt_encrypted,
        user_id=user.id)
    db.session.add(passwordChangeTemp)
    db.session.commit()
    
    reset_link = f'/reset-password/{token}'

    return jsonify({'reset_link': reset_link}), 200


@api.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        passwordChangeTemp = PasswordChangeTemp.query.filter_by(token=token).first()
        if not passwordChangeTemp:
            return jsonify({'error': 'Invalid or expired link.'}), 401
            
        user = User.query.filter_by(id=passwordChangeTemp.user_id).first()
        if not user:
            return jsonify({'error': 'User not found.'}), 404
            
        salt_base64 = utils.aes_decrypt(passwordChangeTemp.salt_encrypted, user.username, SALT_SECRET)
        salt = base64.b64decode(salt_base64)
        email = serializer.loads(token, salt=salt, max_age=3600)
        data = request.get_json()
        new_password = utils.sanitize_content(data.get('password'))
        
        password_verification_message = utils.verify_password(new_password)
        if password_verification_message != "ok":
            return jsonify({'error': password_verification_message}), 400
        
        password_hash = utils.hash_password(new_password, salt)
        user.salt_encrypted = passwordChangeTemp.salt_encrypted
        user.password_hash = password_hash
        user.last_password_change = datetime.datetime.utcnow()
        
        db.session.delete(passwordChangeTemp)
        db.session.commit()
        
        return jsonify({'message': 'Password changed.'}), 200
            
    except Exception as e:
        return jsonify({'error': 'Invalid or expired link.'}), 401


def setup_routes(app):
    app.register_blueprint(api)
    with app.app_context():
        db.create_all()
