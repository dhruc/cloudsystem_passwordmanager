from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, abort
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_caching import Cache
from utils.forms import LoginForm, RegisterForm, SearchForm, AddPasswordForm, EditPasswordForm, SettingsForm, ImportForm, CloudUploadForm
from utils.db_utils import Base, User, VaultEntry, File, init_db, get_user, add_user, get_entries, add_entry, get_entry, update_entry, delete_entry, get_files, add_file, delete_file, SessionLocal
from utils.encryption import derive_key, encrypt, decrypt
from utils.password_utils import generate_password
from utils.cloud.storage import upload_file, download_file, list_files
from utils.cloud.metadata import get_file_metadata
from utils.auth_utils import generate_2fa_secret, verify_2fa, generate_qr
from passlib.hash import bcrypt
import os
import logging
import json
import base64
from functools import wraps
from datetime import datetime, timedelta
import io

app = Flask(__name__)
app.secret_key = 'my-secret-key'  # Fixed key to prevent session invalidation
app.instance_path = os.path.join(os.path.dirname(__file__), 'instance')
os.makedirs(app.instance_path, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1-hour CSRF token validity
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

csrf = CSRFProtect(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

init_db()

# Session validation decorator
def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'user_id' not in session or 'key' not in session:
            logging.warning("Session validation failed: Missing session variables")
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('login'))
        logging.debug(f"Session validated: user_id={session['user_id']}, key={session['key'][:10]}...")
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorator (kept but not applied to login/register for debugging)
def rate_limit(key_prefix, limit=10, window=300):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = f"{key_prefix}:{request.remote_addr}"
            count = cache.get(key) or 0
            if count >= limit:
                logging.warning(f"Rate limit exceeded for {key}")
                abort(429)
            cache.set(key, count + 1, window)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logging.error(f"CSRF error: {str(e)}, Route: {request.path}, Form: {request.form}, Session: {session}")
    flash('CSRF token missing or invalid. Please refresh the page and try again.', 'danger')
    return redirect(request.url), 400

@app.route('/register', methods=['GET', 'POST'])
# @rate_limit('register')  # Disabled for debugging
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        master_pw = form.master_password.data.strip()
        if get_user(username):
            logging.warning(f"User already exists: {username}")
            flash('User exists!', 'danger')
        else:
            try:
                hashed = bcrypt.hash(master_pw)
                add_user(username, hashed)
                logging.info(f"User registered: {username}")
                flash('Registered! Login now.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                logging.error(f"Registration error: {str(e)}")
                flash('Registration failed due to server error', 'danger')
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
# @rate_limit('login')  # Disabled for debugging
def login():
    form = LoginForm()
    if 'logged_in' in session:
        logging.debug("User already logged in, redirecting to dashboard")
        return redirect(url_for('dashboard'))
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        master_pw = form.master_password.data.strip()
        totp = form.totp.data.strip()
        user = get_user(username)
        if user and bcrypt.verify(master_pw, user.master_hash):
            try:
                key = derive_key(master_pw).decode('utf-8')
                if user.twofa_secret and not verify_2fa(decrypt(user.twofa_secret, key).decode('utf-8'), totp):
                    logging.warning(f"Invalid 2FA for user: {username}")
                    flash('Invalid 2FA!', 'danger')
                    return render_template('login.html', form=form)
                session['key'] = key
                session['user_id'] = user.id
                session['logged_in'] = True
                session.permanent = True
                logging.info(f"User {username} logged in successfully, session: {session}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                logging.error(f"Login error for {username}: {str(e)}")
                flash('Login failed due to server error', 'danger')
        else:
            logging.warning(f"Invalid credentials for user: {username}")
            flash('Invalid credentials!', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@require_login
def dashboard():
    form = SearchForm()
    try:
        if request.method == 'POST' and form.validate_on_submit():
            search_query = form.search.data.strip().lower()
            logging.debug(f"Search query by user {session['user_id']}: {search_query}")
            entries = cache.get(f"entries_{session['user_id']}")
            if not entries:
                entries = get_entries(session['key'], session['user_id'])
                cache.set(f"entries_{session['user_id']}", entries, timeout=300)
            if search_query:
                entries = [e for e in entries if search_query in e['site'].lower() or search_query in e['username'].lower()]
            logging.debug(f"Loaded {len(entries)} entries for user {session['user_id']}")
            return render_template('dashboard.html', entries=entries, form=form)
        entries = cache.get(f"entries_{session['user_id']}")
        if not entries:
            entries = get_entries(session['key'], session['user_id'])
            cache.set(f"entries_{session['user_id']}", entries, timeout=300)
        logging.debug(f"Loaded {len(entries)} entries for user {session['user_id']}")
        return render_template('dashboard.html', entries=entries, form=form)
    except Exception as e:
        logging.error(f"Dashboard error for user {session['user_id']}: {str(e)}")
        flash('Failed to load entries', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add', methods=['GET', 'POST'])
@require_login
def add_password():
    form = AddPasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            site = form.site.data.strip()
            username = form.username.data.strip()
            password = form.password.data.strip()
            notes = form.notes.data.strip()
            add_entry(session['key'], session['user_id'], site, username, password, notes)
            cache.delete(f"entries_{session['user_id']}")
            logging.info(f"Password added for user {session['user_id']}: {site}")
            flash('Password added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logging.error(f"Add password error for user {session['user_id']}: {str(e)}")
            flash('Failed to add password', 'danger')
    return render_template('add_password.html', form=form)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@require_login
def edit_password(id):
    form = EditPasswordForm()
    try:
        entry = get_entry(session['key'], id, session['user_id'])
        if not entry:
            logging.warning(f"Entry not found: id={id}, user={session['user_id']}")
            flash('Entry not found!', 'danger')
            return redirect(url_for('dashboard'))
        if request.method == 'POST' and form.validate_on_submit():
            site = form.site.data.strip()
            username = form.username.data.strip()
            password = form.password.data.strip()
            notes = form.notes.data.strip()
            update_entry(session['key'], id, session['user_id'], site, username, password, notes)
            cache.delete(f"entries_{session['user_id']}")
            logging.info(f"Password updated for user {session['user_id']}: id={id}")
            flash('Password updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        form.site.data = entry['site']
        form.username.data = entry['username']
        form.password.data = entry['password']
        form.notes.data = entry['notes']
        return render_template('edit_password.html', entry=entry, form=form)
    except Exception as e:
        logging.error(f"Edit password error for user {session['user_id']}, id={id}: {str(e)}")
        flash('Failed to edit password', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
@require_login
def delete_password(id):
    try:
        delete_entry(id, session['user_id'])
        cache.delete(f"entries_{session['user_id']}")
        logging.info(f"Password deleted for user {session['user_id']}: id={id}")
        flash('Password deleted successfully!', 'success')
    except Exception as e:
        logging.error(f"Delete password error for user {session['user_id']}, id={id}: {str(e)}")
        flash('Failed to delete password', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/generate_password')
@require_login
def generate_pw():
    try:
        return jsonify({'password': generate_password()})
    except Exception as e:
        logging.error(f"Generate password error for user {session['user_id']}: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/get_password/<int:id>')
@require_login
def get_password(id):
    try:
        entry = get_entry(session['key'], id, session['user_id'])
        if entry:
            logging.debug(f"Password retrieved for user {session['user_id']}: id={id}")
            return jsonify({'password': entry['password']})
        logging.warning(f"Password not found: id={id}, user={session['user_id']}")
        return jsonify({'error': 'Not found'}), 404
    except Exception as e:
        logging.error(f"Get password error for user {session['user_id']}, id={id}: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/export')
@require_login
def export_vault():
    try:
        entries = get_entries(session['key'], session['user_id'], decrypt_passwords=True)
        data = json.dumps(entries)
        encrypted_data = encrypt(data.encode('utf-8'), session['key'])
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        logging.info(f"Vault exported for user {session['user_id']}")
        return jsonify({'encrypted_vault': encrypted_b64})
    except Exception as e:
        logging.error(f"Export error for user {session['user_id']}: {str(e)}")
        return jsonify({'error': 'Export failed'}), 500

@app.route('/import', methods=['POST'])
@require_login
def import_vault():
    form = ImportForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            encrypted_data = base64.b64decode(form.encrypted_vault.data.strip().encode('utf-8'))
            data = decrypt(encrypted_data, session['key']).decode('utf-8')
            entries = json.loads(data)
            for entry in entries:
                add_entry(session['key'], session['user_id'], entry['site'], entry['username'], entry['password'], entry.get('notes', ''), skip_encrypt=True)
            cache.delete(f"entries_{session['user_id']}")
            logging.info(f"Vault imported for user {session['user_id']}")
            flash('Vault imported successfully!', 'success')
        except Exception as e:
            logging.error(f"Import error for user {session['user_id']}: {str(e)}")
            flash('Invalid encrypted vault!', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('import.html', form=form)

@app.route('/settings', methods=['GET', 'POST'])
@require_login
def settings():
    form = SettingsForm()
    try:
        with SessionLocal() as db_session:
            user = db_session.query(User).get(session['user_id'])
            if not user:
                logging.warning(f"User not found: id={session['user_id']}")
                flash('User not found', 'danger')
                return redirect(url_for('logout'))
            if request.method == 'POST' and form.validate_on_submit():
                cloud_url = form.cloud_url.data.strip()
                cloud_user = form.cloud_user.data.strip()
                cloud_pw = form.cloud_pw.data.strip()
                if cloud_url and (not cloud_user or not cloud_pw):
                    logging.warning(f"Incomplete cloud credentials for user {session['user_id']}")
                    flash('Complete cloud credentials if using cloud URL', 'warning')
                    return render_template('settings.html', user=user, key=session['key'], form=form)
                user.cloud_url = cloud_url
                user.cloud_user = encrypt(cloud_user.encode('utf-8'), session['key']) if cloud_user else None
                user.cloud_pw = encrypt(cloud_pw.encode('utf-8'), session['key']) if cloud_pw else None
                if form.enable_2fa.data and not user.twofa_secret:
                    secret = generate_2fa_secret()
                    user.twofa_secret = encrypt(secret.encode('utf-8'), session['key'])
                    db_session.commit()
                    qr = generate_qr(secret, user.username)
                    logging.info(f"2FA enabled for user {session['user_id']}")
                    return render_template('settings.html', user=user, key=session['key'], qr_data_uri=qr, form=form)
                db_session.commit()
                logging.info(f"Settings updated for user {session['user_id']}")
                flash('Settings updated!', 'success')
            form.cloud_url.data = user.cloud_url or ''
            form.cloud_user.data = decrypt(user.cloud_user, session['key']).decode('utf-8') if user.cloud_user else ''
            form.cloud_pw.data = decrypt(user.cloud_pw, session['key']).decode('utf-8') if user.cloud_pw else ''
            form.enable_2fa.data = bool(user.twofa_secret)
            return render_template('settings.html', user=user, key=session['key'], form=form)
    except Exception as e:
        logging.error(f"Settings error for user {session['user_id']}: {str(e)}")
        flash('Failed to update settings', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/cloud', methods=['GET'])
@require_login
def cloud():
    form = CloudUploadForm()
    try:
        files = get_files(session['user_id'])
        logging.debug(f"Loaded {len(files)} files for user {session['user_id']}")
        return render_template('cloud.html', files=files, form=form)
    except Exception as e:
        logging.error(f"Cloud error for user {session['user_id']}: {str(e)}")
        flash('Failed to load files', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/cloud/upload', methods=['POST'])
@require_login
def cloud_upload():
    form = CloudUploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        file = form.file.data
        if not file or file.filename == '':
            logging.warning(f"No file selected for user {session['user_id']}")
            flash('No file selected!', 'danger')
            return redirect(url_for('cloud'))
        try:
            local_path = upload_file(file, session['user_id'], session['key'])
            with SessionLocal() as db_session:
                user = db_session.query(User).get(session['user_id'])
                if not user:
                    logging.warning(f"User not found: id={session['user_id']}")
                    flash('User not found', 'danger')
                    return redirect(url_for('logout'))
                add_file(session['user_id'], file.filename, local_path, user.cloud_url, user.cloud_user, user.cloud_pw, session['key'])
            logging.info(f"File uploaded for user {session['user_id']}: {file.filename}")
            flash('File uploaded successfully!', 'success')
        except Exception as e:
            logging.error(f"Upload error for user {session['user_id']}: {str(e)}")
            flash(f'Upload failed: {str(e)}', 'danger')
        return redirect(url_for('cloud'))
    return render_template('cloud.html', form=form, files=get_files(session['user_id']))

@app.route('/cloud/download/<int:file_id>')
@require_login
def cloud_download(file_id):
    try:
        with SessionLocal() as db_session:
            user = db_session.query(User).get(session['user_id'])
            if not user:
                logging.warning(f"User not found: id={session['user_id']}")
                flash('User not found', 'danger')
                return redirect(url_for('logout'))
            file_entry = db_session.query(File).filter_by(id=file_id, user_id=session['user_id']).first()
            if not file_entry:
                logging.warning(f"File not found: id={file_id}, user={session['user_id']}")
                flash('File not found!', 'danger')
                return redirect(url_for('cloud'))
            file_path = download_file(file_entry.path, session['user_id'], session['key'], user.cloud_url, user.cloud_user, user.cloud_pw)
        logging.info(f"File downloaded for user {session['user_id']}: id={file_id}")
        return send_file(file_path, as_attachment=True, download_name=file_entry.filename)
    except Exception as e:
        logging.error(f"Download error for user {session['user_id']}, file_id={file_id}: {str(e)}")
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('cloud'))

@app.route('/cloud/delete/<int:file_id>')
@require_login
def cloud_delete(file_id):
    try:
        with SessionLocal() as db_session:
            user = db_session.query(User).get(session['user_id'])
            if not user:
                logging.warning(f"User not found: id={session['user_id']}")
                flash('User not found', 'danger')
                return redirect(url_for('logout'))
            delete_file(file_id, session['user_id'], user.cloud_url, user.cloud_user, user.cloud_pw, session['key'])
        logging.info(f"File deleted for user {session['user_id']}: id={file_id}")
        flash('File deleted successfully!', 'success')
    except Exception as e:
        logging.error(f"Delete error for user {session['user_id']}, file_id={file_id}: {str(e)}")
        flash(f'Delete failed: {str(e)}', 'danger')
    return redirect(url_for('cloud'))

@app.route('/logout')
def logout():
    logging.info(f"User logged out: user_id={session.get('user_id', 'unknown')}")
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    logging.error(f"404 error: {error}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Server error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limited(error):
    logging.error(f"Rate limit error: {error}")
    return 'Too many requests', 429

if __name__ == '__main__':
    app.run(debug=True)