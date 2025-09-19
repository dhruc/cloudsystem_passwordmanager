from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def derive_key(password: str) -> bytes:
    try:
        password_bytes = password.encode('utf-8')
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        logging.debug(f"Derived key: {key[:10]}...")
        return key
    except Exception as e:
        logging.error(f"Key derivation error: {str(e)}")
        raise

def encrypt(data: bytes, key_str: str) -> bytes:
    try:
        fernet = Fernet(key_str.encode('utf-8'))
        encrypted = fernet.encrypt(data)
        logging.debug("Data encrypted successfully")
        return encrypted
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        raise

def decrypt(data: bytes, key_str: str) -> bytes:
    try:
        fernet = Fernet(key_str.encode('utf-8'))
        decrypted = fernet.decrypt(data)
        logging.debug("Data decrypted successfully")
        return decrypted
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise