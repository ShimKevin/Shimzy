from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Message, PasswordResetToken
from flask_mail import Mail, Message as MailMessage
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import os
from datetime import datetime, timezone
import secrets
from cryptography.fernet import Fernet
import base64
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

# Database Configuration
db_path = os.path.expanduser('~/shimzy_data/instance/prod.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com')

# Print debug info
print(f"Database path: {app.config['SQLALCHEMY_DATABASE_URI']}")
print(f"Instance folder exists: {os.path.exists(os.path.dirname(db_path))}")

# Encryption configuration
fernet_key = os.getenv('FERNET_KEY')
if not fernet_key:
    fernet_key = Fernet.generate_key().decode()
    print(f"Generated new FERNET_KEY: {fernet_key}")
app.config['FERNET_KEY'] = fernet_key

# Initialize extensions
db.init_app(app)
mail = Mail(app)
socketio = SocketIO(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security headers
if os.getenv('FLASK_ENV') == 'production':
    Talisman(app, force_https=True)

# Encryption setup
try:
    fernet = Fernet(app.config['FERNET_KEY'].encode())
except ValueError as e:
    print(f"Invalid FERNET_KEY: {e}")
    print("Generating a new one...")
    new_key = Fernet.generate_key().decode()
    app.config['FERNET_KEY'] = new_key
    fernet = Fernet(new_key.encode())

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def create_tables():
    with app.app_context():
        db.create_all()
        
        # Create test user if none exists
        if not User.query.filter_by(username='test').first():
            user = User(username='test', email='test@example.com')
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
            print("Created test user")

@app.after_request
def add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    if 'Cache-Control' not in resp.headers:
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        print(f"Attempting login for: {request.form['username']}")
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('chat'))
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print(f"Creating user: {request.form['username']}")
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=request.form['username'],
            email=request.form.get('email', ''),
            password=generate_password_hash(request.form['password'])
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('chat'))
    return render_template('auth/register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = user.generate_reset_token()
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg = MailMessage('Password Reset Request', recipients=[user.email])
            msg.body = f"Click this link to reset your password: {reset_url}"
            mail.send(msg)
            
            flash('Password reset link sent to your email', 'success')
            return redirect(url_for('login'))
        
        flash('No account found with that email', 'error')
    return render_template('auth/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or not reset_token.is_valid():
        flash('Invalid or expired token', 'error')
        return redirect(url_for('forgot_password'))
    
    user = reset_token.user
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(request.url)
        
        user.set_password(password)
        reset_token.mark_as_used()
        db.session.commit()
        
        flash('Your password has been updated', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html', token=token)

@app.route('/chat')
@login_required
def chat():
    session_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return render_template('chat/main.html', 
                         username=current_user.username,
                         session_key=session_key)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# WebSocket events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(current_user.username)
        emit('user_status', {'username': current_user.username, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(current_user.username)
        emit('user_status', {'username': current_user.username, 'online': False}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    encrypted_message = fernet.encrypt(data['message'].encode()).decode()
    message = Message(
        sender_id=current_user.id,
        content=encrypted_message,
        room=data.get('room', 'general'),
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(message)
    db.session.commit()
    
    emit('new_message', {
        'sender': current_user.username,
        'message': encrypted_message,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'room': data.get('room', 'general')
    }, room=data.get('room', 'general'))

@socketio.on('decrypt_message')
def handle_decrypt(data):
    if not current_user.is_authenticated:
        return
    
    try:
        decrypted = fernet.decrypt(data['message'].encode()).decode()
        emit('message_decrypted', {
            'id': data['id'],
            'decrypted': decrypted
        })
    except Exception as e:
        print(f"Decryption error: {e}")
        emit('decryption_error', {'id': data['id']})

@socketio.on('call_initiated')
def handle_call(data):
    encrypted_data = {
        'from': current_user.username,
        'to': data['to'],
        'offer': fernet.encrypt(data['offer'].encode()).decode(),
        'type': 'call'
    }
    emit('incoming_call', encrypted_data, room=data['to'])

@socketio.on('call_answer')
def handle_answer(data):
    encrypted_answer = fernet.encrypt(data['answer'].encode()).decode()
    emit('call_answered', {
        'to': data['to'],
        'answer': encrypted_answer
    }, room=data['to'])

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    encrypted_candidate = fernet.encrypt(str(data['candidate']).encode()).decode()
    emit('new_ice_candidate', {
        'to': data['to'],
        'candidate': encrypted_candidate
    }, room=data['to'])

if __name__ == '__main__':
    create_tables()
    
    if os.getenv('RENDER'):  # Running on Render
        port = int(os.environ.get('PORT', 10000))
        # Production mode with Gunicorn+eventlet
        socketio.run(app, host='0.0.0.0', port=port)
    elif os.getenv('FLASK_ENV') == 'production':
        # SSL-enabled production (non-Render)
        import eventlet
        from eventlet import wsgi
        socket = eventlet.listen(('0.0.0.0', int(os.getenv('PORT', 5000))))
        if os.path.exists('fullchain.pem') and os.path.exists('privkey.pem'):
            from eventlet import wrap_ssl
            socket = wrap_ssl(socket,
                            certfile='fullchain.pem',
                            keyfile='privkey.pem',
                            server_side=True)
        wsgi.server(socket, app)
    else:
        # Development mode
        socketio.run(app, debug=True)