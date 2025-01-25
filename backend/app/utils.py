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
