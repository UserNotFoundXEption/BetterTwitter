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
        
        last_password_change = user.last_password_change.timestamp()
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
    
    
def hash_password(password, salt1, salt2):
    constant = "iWn4Ac8m94t827ny9v8732mr829u"
    salt1 = modify_salt(salt1, constant)
    salt2 = modify_salt(salt2, constant)

    salted_password = (password + salt1.hex()).encode()
    hash1 = hash_secret(salted_password, salt1, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.I)
    
    salted_hash1 = (hash1.hex() + salt2.hex()).encode()
    hash2 = hash_secret(salted_hash1, salt2, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.I)
    
    return hash2
    
    
def hash_password_new(password):
    salt1 = os.urandom(32)
    salt2 = os.urandom(16)
    hash2 = hash_password(password, salt1, salt2)
    
    return salt1, salt2, hash2
    
    
def modify_salt(salt, constant):
    salt = salt.hex() + constant
    return salt[::-1].encode()
    
