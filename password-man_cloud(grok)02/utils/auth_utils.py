import pyotp
import qrcode
import io

def generate_2fa_secret():
    return pyotp.random_base32()

def verify_2fa(secret, totp):
    return pyotp.TOTP(secret).verify(totp)

def generate_qr(secret, username):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='PasswordManager')
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return buf.getvalue()