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

# Fix: allow both GET and HEAD
@app.route("/", methods=["GET", "HEAD"])
def index():
    if request.method == "HEAD":
        return "", 200
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# ---------------------- Rest of your routes unchanged ----------------------

@app.route('/register', methods=['GET','POST'])
def register():
    ...
# (keep everything else as in your file)

# ---------------------- App Runner ----------------------
if __name__ == '__main__':
    # Render uses PORT env, disable debug for production
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
