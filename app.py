import os, secrets, mimetypes, datetime, uuid
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
STORAGE = os.path.join(BASE_DIR, 'storage')
os.makedirs(STORAGE, exist_ok=True)
DB_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
SECRET_KEY = os.environ.get('CLOUD_SECRET') or 'change-me-secret-key'
ENC_KEY_PATH = os.path.join(BASE_DIR, 'enc.key')

def get_fernet():
    if not os.path.exists(ENC_KEY_PATH):
        key = Fernet.generate_key()
        with open(ENC_KEY_PATH, 'wb') as f:
            f.write(key)
    else:
        with open(ENC_KEY_PATH, 'rb') as f:
            key = f.read()
    return Fernet(key)

fernet = get_fernet()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 350 * 1024 * 1024  # 350MB per upload

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

DEFAULT_QUOTA = 500 * 1024 * 1024  # 500 MB

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    quota = db.Column(db.Integer, default=DEFAULT_QUOTA)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    stored = db.Column(db.String(300), nullable=False)
    mime = db.Column(db.String(200), nullable=True)
    size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(120), unique=True, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='demo').first():
        demo = User(username='demo', password=generate_password_hash('demo123'))
        db.session.add(demo); db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def user_used_bytes(user_id):
    files = File.query.filter_by(owner_id=user_id).all()
    return sum(f.size for f in files)

@app.template_filter('pretty_size')
def pretty_size_filter(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} TB"

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash('Fill all fields','danger'); return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken','danger'); return redirect(url_for('register'))
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user); db.session.commit()
        flash('Registered! Please login.','success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in','success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out','info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(owner_id=current_user.id).order_by(File.uploaded_at.desc()).all()
    used = user_used_bytes(current_user.id)
    quota = current_user.quota or DEFAULT_QUOTA
    percent = int((used / quota) * 100) if quota else 0
    if percent > 100: percent = 100
    last_share = session.pop('last_share', None)
    return render_template('dashboard.html', files=files, used=used, quota=quota, percent=percent, last_share=last_share)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part','danger'); return redirect(url_for('dashboard'))
    f = request.files['file']
    if f.filename == '':
        flash('No selected file','danger'); return redirect(url_for('dashboard'))
    data = f.read()
    size = len(data)
    used = user_used_bytes(current_user.id)
    quota = current_user.quota or DEFAULT_QUOTA
    if used + size > quota:
        flash('Quota exceeded. Delete files or increase quota.','danger'); return redirect(url_for('dashboard'))
    stored_name = str(uuid.uuid4())
    path = os.path.join(STORAGE, stored_name)
    enc = fernet.encrypt(data)
    with open(path, 'wb') as fh:
        fh.write(enc)
    mime = mimetypes.guess_type(f.filename)[0] or 'application/octet-stream'
    new = File(filename=f.filename, stored=stored_name, mime=mime, size=size, owner_id=current_user.id)
    db.session.add(new); db.session.commit()
    flash('Uploaded successfully','success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        abort(403)
    path = os.path.join(STORAGE, file.stored)
    if not os.path.exists(path): abort(404)
    with open(path, 'rb') as fh:
        dec = fernet.decrypt(fh.read())
    return send_file(BytesIO(dec), as_attachment=True, download_name=file.filename, mimetype=file.mime)

@app.route('/preview/<int:file_id>')
@login_required
def preview(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        abort(403)
    path = os.path.join(STORAGE, file.stored)
    if not os.path.exists(path): abort(404)
    with open(path, 'rb') as fh:
        dec = fernet.decrypt(fh.read())
    if file.mime.startswith('image/') or file.mime.startswith('video/') or file.mime.startswith('text/') or file.mime in ('application/pdf',):
        return send_file(BytesIO(dec), as_attachment=False, download_name=file.filename, mimetype=file.mime)
    flash('Preview not supported for this type','warning'); return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        abort(403)
    path = os.path.join(STORAGE, file.stored)
    try:
        if os.path.exists(path): os.remove(path)
    except Exception:
        pass
    db.session.delete(file); db.session.commit()
    flash('File deleted','success')
    return redirect(url_for('dashboard'))

@app.route('/share/<int:file_id>', methods=['GET','POST'])
@login_required
def share(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        minutes = int(request.form.get('expire', '60'))
        token = secrets.token_urlsafe(24)
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
        sl = ShareLink(token=token, file_id=file.id, expires_at=expires)
        db.session.add(sl); db.session.commit()
        link = url_for('access_share', token=token, _external=True)
        session['last_share'] = {'link': link, 'expires_at': expires.isoformat()}
        flash('Share link created','success')
        return redirect(url_for('dashboard'))
    return render_template('share.html', file=file)

@app.route('/s/<token>')
def access_share(token):
    sl = ShareLink.query.filter_by(token=token).first()
    if not sl or datetime.datetime.utcnow() > sl.expires_at:
        return 'Link expired or invalid', 404
    file = File.query.get_or_404(sl.file_id)
    path = os.path.join(STORAGE, file.stored)
    if not os.path.exists(path): abort(404)
    with open(path, 'rb') as fh:
        dec = fernet.decrypt(fh.read())
    if file.mime.startswith('image/') or file.mime.startswith('video/') or file.mime.startswith('text/') or file.mime in ('application/pdf',):
        return send_file(BytesIO(dec), as_attachment=False, download_name=file.filename, mimetype=file.mime)
    return send_file(BytesIO(dec), as_attachment=True, download_name=file.filename, mimetype=file.mime)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
