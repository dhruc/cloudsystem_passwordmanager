import string
import secrets
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def generate_password(length: int = 16) -> str:
    try:
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(length))
        logging.debug(f"Generated password: {password[:4]}... (length={length})")
        return password
    except Exception as e:
        logging.error(f"Password generation error: {str(e)}")
        raise