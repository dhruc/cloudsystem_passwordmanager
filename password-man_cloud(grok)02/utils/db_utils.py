from sqlalchemy import Column, Integer, String, BLOB, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from utils.encryption import encrypt, decrypt
from datetime import datetime
import os

Base = declarative_base()

# Define engine and Session globally
DB_PATH = os.path.join(os.path.dirname(__file__), '../instance/vault.db')
engine = create_engine(f'sqlite:///{DB_PATH}')
Session = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    master_hash = Column(String)
    twofa_secret = Column(BLOB)
    cloud_url = Column(String)
    cloud_user = Column(BLOB)
    cloud_pw = Column(BLOB)

class VaultEntry(Base):
    __tablename__ = 'vault'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    site = Column(String)
    username = Column(String)
    password_enc = Column(BLOB)
    notes = Column(String)

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    filename = Column(String)
    path = Column(String)
    size = Column(Integer)
    modified = Column(DateTime)

def init_db():
    Base.metadata.create_all(engine)

def get_user(username):
    db_session = Session()
    user = db_session.query(User).filter_by(username=username).first()
    db_session.close()
    return user

def add_user(username, hashed):
    db_session = Session()
    user = User(username=username, master_hash=hashed)
    db_session.add(user)
    db_session.commit()
    db_session.close()

def get_entries(key_str, user_id, decrypt_passwords=False):
    db_session = Session()
    entries = db_session.query(VaultEntry).filter_by(user_id=user_id).all()
    db_session.close()
    result = []
    for entry in entries:
        data = {'id': entry.id, 'site': entry.site, 'username': entry.username, 'notes': entry.notes}
        if decrypt_passwords:
            try:
                data['password'] = decrypt(entry.password_enc, key_str)
            except:
                data['password'] = None
        result.append(data)
    return result

def add_entry(key_str, user_id, site, username, password, notes, skip_encrypt=False):
    db_session = Session()
    password_enc = password.encode('utf-8') if skip_encrypt else encrypt(password, key_str)
    entry = VaultEntry(user_id=user_id, site=site, username=username, password_enc=password_enc, notes=notes)
    db_session.add(entry)
    db_session.commit()
    db_session.close()

def get_entry(key_str, id, user_id):
    db_session = Session()
    entry = db_session.query(VaultEntry).filter_by(id=id, user_id=user_id).first()
    db_session.close()
    if entry:
        try:
            password = decrypt(entry.password_enc, key_str)
        except:
            password = None
        return {'site': entry.site, 'username': entry.username, 'password': password, 'notes': entry.notes}
    return None

def update_entry(key_str, id, user_id, site, username, password, notes):
    db_session = Session()
    entry = db_session.query(VaultEntry).filter_by(id=id, user_id=user_id).first()
    if entry:
        entry.site = site
        entry.username = username
        entry.password_enc = encrypt(password, key_str)
        entry.notes = notes
        db_session.commit()
    db_session.close()

def delete_entry(id, user_id):
    db_session = Session()
    entry = db_session.query(VaultEntry).filter_by(id=id, user_id=user_id).first()
    if entry:
        db_session.delete(entry)
        db_session.commit()
    db_session.close()

def get_files(user_id):
    db_session = Session()
    files = db_session.query(File).filter_by(user_id=user_id).all()
    db_session.close()
    return files

def add_file(user_id, filename, path, cloud_url, cloud_user, cloud_pw, key_str):
    db_session = Session()
    size = os.path.getsize(path)
    modified = datetime.fromtimestamp(os.path.getmtime(path))
    file = File(user_id=user_id, filename=filename, path=path, size=size, modified=modified)
    db_session.add(file)
    db_session.commit()
    if cloud_url and cloud_user and cloud_pw:
        from utils.cloud.storage import upload_to_cloud
        upload_to_cloud(path, cloud_url, f'files/{user_id}/{filename}', decrypt(cloud_user, key_str), decrypt(cloud_pw, key_str))
    db_session.close()

def delete_file(file_id, user_id, cloud_url, cloud_user, cloud_pw):
    db_session = Session()
    file = db_session.query(File).filter_by(id=file_id, user_id=user_id).first()
    if file:
        if os.path.exists(file.path):
            os.remove(file.path)
        if cloud_url and cloud_user and cloud_pw:
            from utils.cloud.storage import delete_from_cloud
            delete_from_cloud(cloud_url, f'files/{user_id}/{file.filename}', decrypt(cloud_user, key_str), decrypt(cloud_pw, key_str))
        db_session.delete(file)
        db_session.commit()
    db_session.close()