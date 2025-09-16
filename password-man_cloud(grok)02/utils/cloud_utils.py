import requests
from requests.auth import HTTPBasicAuth

def upload_to_cloud(local_path, cloud_url, remote_path, username, password):
    with open(local_path, 'rb') as f:
        response = requests.put(f'{cloud_url}/remote.php/dav/files/{username}/{remote_path}', data=f, auth=HTTPBasicAuth(username, password))
    response.raise_for_status()

def download_from_cloud(cloud_url, remote_path, local_path, username, password):
    response = requests.get(f'{cloud_url}/remote.php/dav/files/{username}/{remote_path}', auth=HTTPBasicAuth(username, password))
    response.raise_for_status()
    with open(local_path, 'wb') as f:
        f.write(response.content)

def read_cloud_metadata(cloud_url, remote_path, username, password):
    headers = {'Depth': '0'}
    response = requests.request('PROPFIND', f'{cloud_url}/remote.php/dav/files/{username}/{remote_path}', auth=HTTPBasicAuth(username, password), headers=headers)
    response.raise_for_status()
    return {'version': 0}

def write_to_cloud(cloud_url, remote_path, data, username, password):
    response = requests.put(f'{cloud_url}/remote.php/dav/files/{username}/{remote_path}', data=data, auth=HTTPBasicAuth(username, password))
    response.raise_for_status()

def delete_from_cloud(cloud_url, remote_path, username, password):
    response = requests.delete(f'{cloud_url}/remote.php/dav/files/{username}/{remote_path}', auth=HTTPBasicAuth(username, password))
    response.raise_for_status()