# utils.py
import os
from datetime import datetime, timedelta
from jose import jwt
from typing import Optional
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import hmac, hashlib

SECRET_KEY = os.getenv("SECRET_KEY", "fallbacksecret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
FERNET_KEY = os.getenv("FERNET_KEY")  # must exist
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "webhooksecretfallback")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_webhook_signature(payload_bytes: bytes, signature_header: str) -> bool:
    # signature_header expected as hex HMAC-SHA256
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload_bytes, digestmod=hashlib.sha256)
    expected = mac.hexdigest()
    return hmac.compare_digest(expected, signature_header)

# Fernet helper for encrypt/decrypt metadata
def get_fernet():
    if not FERNET_KEY:
        raise RuntimeError("FERNET_KEY not set in env")
    return Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def encrypt_metadata(obj: dict) -> str:
    f = get_fernet()
    import json
    b = json.dumps(obj).encode()
    return f.encrypt(b).decode()

def decrypt_metadata(token: str) -> dict:
    f = get_fernet()
    import json
    b = f.decrypt(token.encode())
    return json.loads(b.decode())
