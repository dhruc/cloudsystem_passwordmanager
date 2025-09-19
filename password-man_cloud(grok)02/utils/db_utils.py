from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from utils.encryption import encrypt, decrypt
import os
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    master_hash = Column(String, nullable=False)
    twofa_secret = Column(Text)
    cloud_url = Column(String)
    cloud_user = Column(Text)
    cloud_pw = Column(Text)

class VaultEntry(Base):
    __tablename__ = 'vault_entries'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    site = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(Text, nullable=False)
    notes = Column(Text)
    created = Column(DateTime, default=datetime.utcnow)

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    filename = Column(String, nullable=False)
    path = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    modified = Column(DateTime, default=datetime.utcnow)

engine = create_engine('sqlite:///instance/passwords.db', echo=False)
SessionLocal = sessionmaker(bind=engine)

def init_db():
    try:
        Base.metadata.create_all(engine)
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization error: {str(e)}")
        raise

def get_user(username):
    try:
        with SessionLocal() as session:
            user = session.query(User).filter_by(username=username).first()
            logging.debug(f"Queried user: {username}, found: {user is not None}")
            return user
    except Exception as e:
        logging.error(f"Error querying user {username}: {str(e)}")
        return None

def add_user(username, master_hash):
    try:
        with SessionLocal() as session:
            user = User(username=username, master_hash=master_hash)
            session.add(user)
            session.commit()
            logging.info(f"Added user: {username}")
            return user
    except Exception as e:
        logging.error(f"Error adding user {username}: {str(e)}")
        session.rollback()
        raise

def get_entries(key, user_id, decrypt_passwords=False):
    try:
        with SessionLocal() as session:
            entries = session.query(VaultEntry).filter_by(user_id=user_id).all()
            decrypted_entries = []
            for entry in entries:
                decrypted_entry = {
                    'id': entry.id,
                    'site': decrypt(entry.site, key).decode('utf-8'),
                    'username': decrypt(entry.username, key).decode('utf-8'),
                    'password': decrypt(entry.password, key).decode('utf-8') if decrypt_passwords else '****',
                    'notes': decrypt(entry.notes, key).decode('utf-8') if entry.notes else '',
                    'created': entry.created
                }
                decrypted_entries.append(decrypted_entry)
            logging.debug(f"Retrieved {len(entries)} entries for user {user_id}")
            return decrypted_entries
    except Exception as e:
        logging.error(f"Error retrieving entries for user {user_id}: {str(e)}")
        return []

def add_entry(key, user_id, site, username, password, notes, skip_encrypt=False):
    try:
        with SessionLocal() as session:
            if skip_encrypt:
                encrypted_site = site.encode('utf-8')
                encrypted_username = username.encode('utf-8')
                encrypted_password = password.encode('utf-8')
                encrypted_notes = notes.encode('utf-8') if notes else None
            else:
                encrypted_site = encrypt(site.encode('utf-8'), key)
                encrypted_username = encrypt(username.encode('utf-8'), key)
                encrypted_password = encrypt(password.encode('utf-8'), key)
                encrypted_notes = encrypt(notes.encode('utf-8'), key) if notes else None
            entry = VaultEntry(
                user_id=user_id,
                site=encrypted_site,
                username=encrypted_username,
                password=encrypted_password,
                notes=encrypted_notes
            )
            session.add(entry)
            session.commit()
            logging.info(f"Added entry for user {user_id}: {site}")
    except Exception as e:
        logging.error(f"Error adding entry for user {user_id}: {str(e)}")
        session.rollback()
        raise

def get_entry(key, entry_id, user_id):
    try:
        with SessionLocal() as session:
            entry = session.query(VaultEntry).filter_by(id=entry_id, user_id=user_id).first()
            if not entry:
                logging.warning(f"Entry not found: id={entry_id}, user={user_id}")
                return None
            decrypted_entry = {
                'id': entry.id,
                'site': decrypt(entry.site, key).decode('utf-8'),
                'username': decrypt(entry.username, key).decode('utf-8'),
                'password': decrypt(entry.password, key).decode('utf-8'),
                'notes': decrypt(entry.notes, key).decode('utf-8') if entry.notes else '',
                'created': entry.created
            }
            logging.debug(f"Retrieved entry {entry_id} for user {user_id}")
            return decrypted_entry
    except Exception as e:
        logging.error(f"Error retrieving entry {entry_id} for user {user_id}: {str(e)}")
        return None

def update_entry(key, entry_id, user_id, site, username, password, notes):
    try:
        with SessionLocal() as session:
            entry = session.query(VaultEntry).filter_by(id=entry_id, user_id=user_id).first()
            if not entry:
                logging.warning(f"Entry not found for update: id={entry_id}, user={user_id}")
                return
            entry.site = encrypt(site.encode('utf-8'), key)
            entry.username = encrypt(username.encode('utf-8'), key)
            entry.password = encrypt(password.encode('utf-8'), key)
            entry.notes = encrypt(notes.encode('utf-8'), key) if notes else None
            session.commit()
            logging.info(f"Updated entry {entry_id} for user {user_id}")
    except Exception as e:
        logging.error(f"Error updating entry {entry_id} for user {user_id}: {str(e)}")
        session.rollback()
        raise

def delete_entry(entry_id, user_id):
    try:
        with SessionLocal() as session:
            entry = session.query(VaultEntry).filter_by(id=entry_id, user_id=user_id).first()
            if not entry:
                logging.warning(f"Entry not found for deletion: id={entry_id}, user={user_id}")
                return
            session.delete(entry)
            session.commit()
            logging.info(f"Deleted entry {entry_id} for user {user_id}")
    except Exception as e:
        logging.error(f"Error deleting entry {entry_id} for user {user_id}: {str(e)}")
        session.rollback()
        raise

def get_files(user_id):
    try:
        with SessionLocal() as session:
            files = session.query(File).filter_by(user_id=user_id).all()
            logging.debug(f"Retrieved {len(files)} files for user {user_id}")
            return files
    except Exception as e:
        logging.error(f"Error retrieving files for user {user_id}: {str(e)}")
        return []

def add_file(user_id, filename, path, cloud_url, cloud_user, cloud_pw, key):
    try:
        with SessionLocal() as session:
            file_size = os.path.getsize(path)
            file = File(
                user_id=user_id,
                filename=filename,
                path=path,
                size=file_size
            )
            session.add(file)
            session.commit()
            logging.info(f"Added file {filename} for user {user_id}")
            # Upload to cloud if configured
            if cloud_url and cloud_user and cloud_pw:
                try:
                    from utils.cloud_utils import upload_to_cloud
                    cloud_user_str = decrypt(cloud_user, key).decode('utf-8')
                    cloud_pw_str = decrypt(cloud_pw, key).decode('utf-8')
                    remote_path = f'files/{user_id}/{filename}'
                    upload_to_cloud(path, cloud_url, remote_path, cloud_user_str, cloud_pw_str)
                    logging.info(f"Uploaded file {filename} to cloud")
                except Exception as e:
                    logging.error(f"Failed to upload {filename} to cloud: {str(e)}")
    except Exception as e:
        logging.error(f"Error adding file {filename} for user {user_id}: {str(e)}")
        session.rollback()
        raise

def delete_file(file_id, user_id, cloud_url, cloud_user, cloud_pw, key):
    try:
        with SessionLocal() as session:
            file = session.query(File).filter_by(id=file_id, user_id=user_id).first()
            if not file:
                logging.warning(f"File not found for deletion: id={file_id}, user={user_id}")
                return
            if os.path.exists(file.path):
                os.remove(file.path)
            session.delete(file)
            session.commit()
            logging.info(f"Deleted file {file_id} for user {user_id}")
            # Delete from cloud if configured
            if cloud_url and cloud_user and cloud_pw:
                try:
                    from utils.cloud_utils import delete_from_cloud
                    cloud_user_str = decrypt(cloud_user, key).decode('utf-8')
                    cloud_pw_str = decrypt(cloud_pw, key).decode('utf-8')
                    remote_path = f'files/{user_id}/{file.filename}'
                    delete_from_cloud(cloud_url, remote_path, cloud_user_str, cloud_pw_str)
                    logging.info(f"Deleted file {file.filename} from cloud")
                except Exception as e:
                    logging.error(f"Failed to delete {file.filename} from cloud: {str(e)}")
    except Exception as e:
        logging.error(f"Error deleting file {file_id} for user {user_id}: {str(e)}")
        session.rollback()
        raise
