from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import os
import logging
import json
from utils.encryption import derive_key, encrypt, decrypt
from utils.password_utils import generate_password
from utils.db_utils import Base, User, VaultEntry, File, init_db, get_user, add_user, get_entries, add_entry, get_entry, update_entry, delete_entry, get_files, add_file, delete_file, Session
from utils.cloud.storage import upload_file, download_file, list_files
from utils.cloud.metadata import get_file_metadata
from utils.auth_utils import generate_2fa_secret, verify_2fa, generate_qr
from passlib.hash import bcrypt
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.instance_path = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(app.instance_path, exist_ok=True)

logging.basicConfig(filename='app.log', level=logging.INFO)

# Initialize database
init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        master_pw = request.form['master_password']
        if get_user(username):
            flash('User exists!', 'danger')
        else:
            hashed = bcrypt.hash(master_pw)
            add_user(username, hashed)
            flash('Registered! Login now.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        master_pw = request.form['master_password']
        totp = request.form.get('totp')
        user = get_user(username)
        if user and bcrypt.verify(master_pw, user.master_hash):
            key = derive_key(master_pw).decode('utf-8')
            if user.twofa_secret and not verify_2fa(decrypt(user.twofa_secret, key), totp):
                flash('Invalid 2FA!', 'danger')
                return render_template('login.html')
            session['key'] = key
            session['user_id'] = user.id
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    entries = get_entries(session['key'], session['user_id'])
    return render_template('dashboard.html', entries=entries)

@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        add_entry(session['key'], session['user_id'], site, username, password, notes)
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_password.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    entry = get_entry(session['key'], id, session['user_id'])
    if not entry:
        flash('Entry not found!', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        update_entry(session['key'], id, session['user_id'], site, username, password, notes)
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_password.html', entry=entry)

@app.route('/delete/<int:id>')
def delete_password(id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    delete_entry(id, session['user_id'])
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/generate_password')
def generate_pw():
    return jsonify({'password': generate_password()})

@app.route('/get_password/<int:id>')
def get_password(id):
    if 'logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    entry = get_entry(session['key'], id, session['user_id'])
    if entry:
        return jsonify({'password': entry['password']})
    return jsonify({'error': 'Not found'}), 404

@app.route('/export')
def export_vault():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    entries = get_entries(session['key'], session['user_id'], decrypt_passwords=True)
    data = json.dumps(entries)
    encrypted_data = encrypt(data.encode('utf-8'), session['key'])
    return jsonify({'encrypted_vault': encrypted_data.decode('utf-8')})

@app.route('/import', methods=['POST'])
def import_vault():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    encrypted_data = request.form['encrypted_vault']
    try:
        data = decrypt(encrypted_data.encode('utf-8'), session['key']).decode('utf-8')
        entries = json.loads(data)
        for entry in entries:
            add_entry(session['key'], session['user_id'], entry['site'], entry['username'], entry['password'], entry.get('notes', ''), skip_encrypt=True)
        flash('Vault imported successfully!', 'success')
    except Exception as e:
        logging.error(f'Import error: {e}')
        flash('Invalid encrypted vault!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    db_session = Session()
    user = db_session.query(User).get(session['user_id'])
    if request.method == 'POST':
        cloud_url = request.form.get('cloud_url')
        cloud_user = request.form.get('cloud_user')
        cloud_pw = request.form.get('cloud_pw')
        user.cloud_url = cloud_url
        user.cloud_user = encrypt(cloud_user.encode('utf-8'), session['key']) if cloud_user else None
        user.cloud_pw = encrypt(cloud_pw.encode('utf-8'), session['key']) if cloud_pw else None
        if 'enable_2fa' in request.form:
            if not user.twofa_secret:
                secret = generate_2fa_secret()
                user.twofa_secret = encrypt(secret.encode('utf-8'), session['key'])
                qr = generate_qr(secret, user.username)
                db_session.commit()
                return send_file(io.BytesIO(qr), mimetype='image/png')
        db_session.commit()
        flash('Settings updated!', 'success')
    db_session.close()
    return render_template('settings.html', user=user, key=session['key'])

@app.route('/cloud', methods=['GET', 'POST'])
def cloud():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    files = get_files(session['user_id'])
    return render_template('cloud.html', files=files)

@app.route('/cloud/upload', methods=['POST'])
def cloud_upload():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('cloud'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('cloud'))
    try:
        filename = upload_file(file, session['user_id'], session['key'])
        db_session = Session()
        user = db_session.query(User).get(session['user_id'])
        add_file(session['user_id'], file.filename, filename, user.cloud_url, user.cloud_user, user.cloud_pw, session['key'])
        db_session.close()
        flash('File uploaded successfully!', 'success')
    except Exception as e:
        logging.error(f'Upload error: {str(e)}')
        flash(f'Upload failed: {str(e)}', 'danger')
    return redirect(url_for('cloud'))

@app.route('/cloud/download/<int:file_id>')
def cloud_download(file_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    try:
        db_session = Session()
        user = db_session.query(User).get(session['user_id'])
        file = db_session.query(File).filter_by(id=file_id, user_id=session['user_id']).first()
        db_session.close()
        if not file:
            flash('File not found!', 'danger')
            return redirect(url_for('cloud'))
        file_path = download_file(file.path, session['user_id'], session['key'], user.cloud_url, user.cloud_user, user.cloud_pw)
        return send_file(file_path, as_attachment=True, download_name=file.filename)
    except Exception as e:
        logging.error(f'Download error: {e}')
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('cloud'))

@app.route('/cloud/delete/<int:file_id>')
def cloud_delete(file_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    try:
        db_session = Session()
        user = db_session.query(User).get(session['user_id'])
        delete_file(file_id, session['user_id'], user.cloud_url, user.cloud_user, user.cloud_pw)
        db_session.close()
        flash('File deleted successfully!', 'success')
    except Exception as e:
        logging.error(f'Delete error: {e}')
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('cloud'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)