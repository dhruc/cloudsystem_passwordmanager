import secrets
import string

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def check_strength(password):
    if len(password) < 8:
        return 'Weak'
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    if score >= 3 and len(password) >= 12:
        return 'Strong'
    elif score >= 2:
        return 'Medium'
    return 'Weak'