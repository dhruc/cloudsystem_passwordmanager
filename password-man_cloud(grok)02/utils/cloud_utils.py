import os
import requests
import logging
from typing import Optional

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def upload_to_cloud(local_path: str, cloud_url: str, remote_path: str, username: str, password: str) -> None:
    try:
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file {local_path} not found")
        with open(local_path, 'rb') as f:
            response = requests.put(
                f"{cloud_url.rstrip('/')}/remote.php/dav/files/{username}/{remote_path.lstrip('/')}",
                data=f,
                auth=(username, password)
            )
            response.raise_for_status()
        logging.info(f"Uploaded to cloud: {remote_path}")
    except Exception as e:
        logging.error(f"Cloud upload error: {str(e)}")
        raise

def download_from_cloud(cloud_url: str, remote_path: str, local_path: str, username: str, password: str) -> None:
    try:
        response = requests.get(
            f"{cloud_url.rstrip('/')}/remote.php/dav/files/{username}/{remote_path.lstrip('/')}",
            auth=(username, password)
        )
        response.raise_for_status()
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, 'wb') as f:
            f.write(response.content)
        logging.info(f"Downloaded from cloud: {remote_path}")
    except Exception as e:
        logging.error(f"Cloud download error: {str(e)}")
        raise

def delete_from_cloud(cloud_url: str, remote_path: str, username: str, password: str) -> None:
    try:
        response = requests.delete(
            f"{cloud_url.rstrip('/')}/remote.php/dav/files/{username}/{remote_path.lstrip('/')}",
            auth=(username, password)
        )
        response.raise_for_status()
        logging.info(f"Deleted from cloud: {remote_path}")
    except Exception as e:
        logging.error(f"Cloud delete error: {str(e)}")
        raise