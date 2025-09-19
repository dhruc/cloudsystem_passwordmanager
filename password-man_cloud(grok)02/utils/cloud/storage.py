import os
from flask_caching import Cache
from werkzeug.utils import secure_filename
from utils.encryption import encrypt, decrypt
from utils.cloud_utils import upload_to_cloud, download_from_cloud, delete_from_cloud
from typing import Optional
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

cache = Cache(config={'CACHE_TYPE': 'simple'})

def upload_file(file, user_id: int, key_str: str) -> str:
    try:
        if not file or not file.filename:
            raise ValueError("No file provided or empty filename")
        storage_dir = os.path.join('storage', str(user_id))
        os.makedirs(storage_dir, exist_ok=True)
        filename = secure_filename(file.filename) or 'unnamed_file'
        local_path = os.path.join(storage_dir, filename)

        if not os.access(os.path.dirname(local_path), os.W_OK):
            raise PermissionError(f"No write permission for {storage_dir}")

        chunk_size = 8192
        encrypted_content = b''
        while True:
            chunk = file.stream.read(chunk_size)
            if not chunk:
                break
            encrypted_content += encrypt(chunk, key_str)

        with open(local_path, 'wb') as f:
            f.write(encrypted_content)

        cache.set(
            f"file_{user_id}_{filename}",
            {'size': os.path.getsize(local_path), 'modified': os.path.getmtime(local_path)},
            timeout=3600
        )

        logging.info(f"File uploaded: {filename} for user {user_id}")
        return local_path

    except Exception as e:
        logging.error(f"Upload error for user {user_id}, file {file.filename if file else 'None'}: {str(e)}")
        raise

def download_file(path: str, user_id: int, key_str: str, cloud_url: Optional[str] = None, cloud_user: Optional[bytes] = None, cloud_pw: Optional[bytes] = None) -> str:
    try:
        if not os.path.exists(path):
            if cloud_url and cloud_user and cloud_pw:
                temp_path = os.path.join('storage', str(user_id), f'temp_{os.path.basename(path)}')
                cloud_user_str = decrypt(cloud_user, key_str).decode('utf-8') if cloud_user else None
                cloud_pw_str = decrypt(cloud_pw, key_str).decode('utf-8') if cloud_pw else None
                remote_path = f'files/{user_id}/{os.path.basename(path)}'
                download_from_cloud(cloud_url, remote_path, temp_path, cloud_user_str, cloud_pw_str)
                path = temp_path
            else:
                raise FileNotFoundError(f"File {path} not found locally and no cloud configured")

        if not os.access(path, os.R_OK):
            raise PermissionError(f"No read permission for {path}")

        chunk_size = 8192
        decrypted_content = b''
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                decrypted_content += decrypt(chunk, key_str)

        temp_path = os.path.join('storage', str(user_id), f'decrypted_{os.path.basename(path)}')
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        with open(temp_path, 'wb') as f:
            f.write(decrypted_content)

        logging.info(f"File downloaded: {path} for user {user_id}")
        return temp_path

    except Exception as e:
        logging.error(f"Download error for user {user_id}, file {path}: {str(e)}")
        raise

def list_files(user_id: int) -> list:
    try:
        storage_dir = os.path.join('storage', str(user_id))
        os.makedirs(storage_dir, exist_ok=True)
        files = [
            f for f in os.listdir(storage_dir)
            if os.path.isfile(os.path.join(storage_dir, f)) and not f.startswith('temp_') and not f.startswith('decrypted_')
        ]
        logging.info(f"Listed files for user {user_id}: {len(files)} files")
        return files

    except Exception as e:
        logging.error(f"List files error for user {user_id}: {str(e)}")
        raise