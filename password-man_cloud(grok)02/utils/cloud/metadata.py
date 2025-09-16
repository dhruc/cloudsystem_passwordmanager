import os
from datetime import datetime

def get_file_metadata(path):
    return {
        'size': os.path.getsize(path),
        'modified': datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
    }