from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

def derive_key(password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = base64.urlsafe_b64decode(salt + b'==')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt(data: bytes, key_str: str) -> bytes:
    key = key_str.encode('utf-8')
    f = Fernet(key)
    return f.encrypt(data if isinstance(data, bytes) else data.encode('utf-8'))

def decrypt(token: bytes, key_str: str) -> bytes:
    key = key_str.encode('utf-8')
    f = Fernet(key)
    return f.decrypt(token)