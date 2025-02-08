import rsa
import jwt
from flask import jsonify, request
import math
from collections import Counter
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import bleach
import requests
import re
from io import BytesIO
from PIL import Image
import os
from argon2.low_level import hash_secret, Type
from app.models import User
import datetime
import hashlib
from Crypto.Cipher import AES
import base64
import sys

def sign_message(message, private_key):
    private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    return rsa.sign(message.encode(), private_key, 'SHA-256').hex()


def verify_message(message, signature, public_key):
    public_key = rsa.PublicKey.load_pkcs1(public_key.encode())
    try:
        rsa.verify(message.encode(), bytes.fromhex(signature), public_key)
        return True
    except rsa.VerificationError:
        return False


def validate_token(SECRET_KEY, request):
    auth_header = request.headers.get('Authorization', '')
    if auth_header is None:
        raise InvalidTokenError
        
    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user = User.query.get(decoded['user_id'])
        
        last_password_change_timestamp = user.last_password_change.timestamp()
        last_password_change = datetime.datetime.utcfromtimestamp(last_password_change_timestamp)
        token_iat = datetime.datetime.utcfromtimestamp(decoded['iat'])
        if last_password_change > token_iat:
            raise ExpiredSignatureError
            
        return decoded
        
    except (ExpiredSignatureError, InvalidTokenError) as e:
        raise type(e)(str(e))


def verify_password(password):
    if not password.isalnum():
        return 'Password has to be alphanueric.'
    if len(password) < 8:
        return "Password is too short. (minimum 8 characters)"
    if len(password) > 32:
        return "Password is too long. (max 32 characters)"
    if not is_password_strong(password):
        return "Password is too weak."
    if not is_password_uncommon(password):
        return "Password is too common."
    return "ok"


def is_password_strong(password):
    counts = Counter(password)
    length = len(password)
    entropy = 0
    for char, count in counts.items():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy > 3


def is_password_uncommon(password):
    with open('./wordlist.txt', 'r') as wordlist:
        for line in wordlist:
            if password == line.strip():
                return False
        return True


def sanitize_content(content):
    allowed_tags = ['b', 'i', 'strong', 'em', 'a', 'img']
    allowed_attrs = {'a': ['href', 'title'], 'img': ['src', 'alt']}
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=False)


def validate_image_size(image_url):
    try:
        response = requests.get(image_url)
        response.raise_for_status()

        img = Image.open(BytesIO(response.content))

        width, height = img.size
        if width > 1920 or height > 1080:
            return False, f"Image dimensions ({width}x{height}) exceed 1920x1080."
        return True, f"Image dimensions are within the limit ({width}x{height})."

    except Exception as e:
        return False, f"Failed to validate image: {str(e)}"


def extract_image_url(content):
    pattern = r"!\[.*?\]\((.*?)\)"
    match = re.search(pattern, content)
    return match.group(1) if match else None
    
    
def hash_password(password, salt):
    salted_password = (password + salt.hex()).encode()
    password_hash = hash_secret(salted_password, salt, time_cost=8, memory_cost=262144, parallelism=1, hash_len=32, type=Type.I)
    return password_hash
    

def get_env_var(var_name):
    try:
        return os.environ[var_name]
    except KeyError:
        raise RuntimeError(f"Not found: {var_name}")
        

def aes_encrypt(data, username, base_secret):
    key = hashlib.sha256(f"{base_secret}{username}".encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    encrypted_data = cipher.nonce + ciphertext + tag
    return base64.b64encode(encrypted_data).decode()
    

def aes_decrypt(encrypted_data, username, base_secret):
    key = hashlib.sha256(f"{base_secret}{username}".encode()).digest()
    encrypted_data = base64.b64decode(encrypted_data)
    
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()
    
