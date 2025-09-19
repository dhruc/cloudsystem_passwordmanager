import os
import logging
from typing import Dict

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def get_file_metadata(path: str) -> Dict:
    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} not found")
        metadata = {
            'size': os.path.getsize(path),
            'modified': os.path.getmtime(path)
        }
        logging.debug(f"Retrieved metadata for {path}: {metadata}")
        return metadata
    except Exception as e:
        logging.error(f"Metadata error for {path}: {str(e)}")
        raise