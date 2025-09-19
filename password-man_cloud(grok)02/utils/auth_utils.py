import pyotp
import qrcode
import io
import base64
import logging
from typing import Optional

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def generate_2fa_secret() -> str:
    """
    Generate a new TOTP secret for 2FA.
    Returns:
        str: Base32-encoded TOTP secret.
    """
    try:
        secret = pyotp.random_base32()
        logging.debug(f"Generated 2FA secret: {secret[:4]}...")
        return secret
    except Exception as e:
        logging.error(f"2FA secret generation error: {str(e)}")
        raise

def verify_2fa(secret: str, totp_code: str) -> bool:
    """
    Verify a TOTP code against the provided secret.
    Args:
        secret (str): Base32-encoded TOTP secret.
        totp_code (str): User-provided TOTP code.
    Returns:
        bool: True if the code is valid, False otherwise.
    """
    try:
        totp = pyotp.TOTP(secret)
        verified = totp.verify(totp_code)
        logging.debug(f"2FA verification {'successful' if verified else 'failed'} for code: {totp_code}")
        return verified
    except Exception as e:
        logging.error(f"2FA verification error: {str(e)}")
        return False

def generate_qr(secret: str, username: str) -> str:
    """
    Generate a QR code for 2FA setup.
    Args:
        secret (str): Base32-encoded TOTP secret.
        username (str): Username for the TOTP issuer.
    Returns:
        str: Data URI of the QR code image.
    """
    try:
        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="PasswordManager")
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        data_uri = f"data:image/png;base64,{img_str}"
        logging.debug(f"Generated 2FA QR code for user: {username}")
        return data_uri
    except Exception as e:
        logging.error(f"QR code generation error for user {username}: {str(e)}")
        raise