import os
from utils.encryption import encrypt, decrypt
from utils.cloud_utils import upload_to_cloud, download_from_cloud, delete_from_cloud

def upload_file(file, user_id, key_str):
    storage_dir = os.path.join('storage', str(user_id))
    os.makedirs(storage_dir, exist_ok=True)
    filename = file.filename
    local_path = os.path.join(storage_dir, filename)
    
    # Read file content as bytes
    content = file.read()
    
    # Encrypt as bytes (no decoding)
    encrypted_content = encrypt(content, key_str)
    
    # Save locally
    with open(local_path, 'wb') as f:
        f.write(encrypted_content)
    
    return local_path

def download_file(path, user_id, key_str, cloud_url=None, cloud_user=None, cloud_pw=None):
    if cloud_url and cloud_user and cloud_pw:
        try:
            cloud_user = decrypt(cloud_user, key_str) if cloud_user else None
            cloud_pw = decrypt(cloud_pw, key_str) if cloud_pw else None
            remote_path = f'files/{user_id}/{os.path.basename(path)}'
            temp_path = os.path.join('storage', str(user_id), 'temp_' + os.path.basename(path))
            download_from_cloud(cloud_url, remote_path, temp_path, cloud_user, cloud_pw)
            path = temp_path
        except Exception as e:
            raise Exception(f"Cloud download failed: {e}")
    
    with open(path, 'rb') as f:
        encrypted_content = f.read()
    content = decrypt(encrypted_content, key_str)
    
    temp_path = os.path.join('storage', str(user_id), 'decrypted_' + os.path.basename(path))
    with open(temp_path, 'wb') as f:  # Write as bytes
        f.write(content.encode('utf-8') if isinstance(content, str) else content)
    return temp_path

def list_files(user_id):
    storage_dir = os.path.join('storage', str(user_id))
    os.makedirs(storage_dir, exist_ok=True)
    return [f for f in os.listdir(storage_dir) if os.path.isfile(os.path.join(storage_dir, f))]