from flask import Flask, request, jsonify, render_template, redirect, url_for, abort
from cryptography.fernet import Fernet
import secrets
import sqlite3
from datetime import datetime, timedelta
import os
from functools import wraps
from flask_restx import Api, Resource, fields, Namespace

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-123')
DB_FILE = "secrets.db"
KEY_FILE = "secret.key"

# Конфигурация ограничений
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '').split(',') if os.environ.get('ALLOWED_IPS') else []
ALLOWED_USER_AGENTS = os.environ.get('ALLOWED_USER_AGENTS', '').split(',') if os.environ.get('ALLOWED_USER_AGENTS') else []
BLOCKED_IPS = ['10.0.22.1']

# Генерация ключа шифрования
def get_encryption_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

cipher = Fernet(get_encryption_key())

# Инициализация БД
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            encrypted_data TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            is_encrypted BOOLEAN DEFAULT 1
        )
        """)
        conn.execute("DELETE FROM secrets WHERE expires_at < datetime('now')")

# Шифрование/дешифрование
def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data.encode()).decode()

# Декоратор проверки доступа
def access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        if client_ip in BLOCKED_IPS:
            app.logger.warning(f"Access blocked for IP: {client_ip}")
            abort(403, description="Доступ с вашего IP-адреса запрещен")
        
        if not ALLOWED_IPS and not ALLOWED_USER_AGENTS:
            return f(*args, **kwargs)

        user_agent = request.user_agent.string
        ip_allowed = not ALLOWED_IPS or client_ip in ALLOWED_IPS
        ua_allowed = not ALLOWED_USER_AGENTS or any(allowed_ua in user_agent for allowed_ua in ALLOWED_USER_AGENTS if allowed_ua)

        if ip_allowed or ua_allowed:
            return f(*args, **kwargs)
        else:
            app.logger.warning(f"Access denied for IP: {client_ip} and User-Agent: {user_agent}")
            abort(403)
    return decorated_function

# Веб-интерфейс (роуты определены до инициализации API)
@app.route('/', methods=['GET', 'POST'])
@access_required
def index():
    if request.method == 'POST':
        secret_text = request.form.get('secret')
        if not secret_text:
            return render_template('index.html', error="Сообщение не может быть пустым")
        
        secret_id = secrets.token_urlsafe(16)
        expires_at = datetime.now() + timedelta(days=1)
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO secrets (id, encrypted_data, expires_at) VALUES (?, ?, ?)",
                (secret_id, encrypt_data(secret_text), expires_at))
        
        return redirect(url_for('share_link', secret_id=secret_id))
    return render_template('index.html')

@app.route('/share/<secret_id>')
@access_required
def share_link(secret_id):
    return render_template('share.html', secret_id=secret_id)

@app.route('/view/<secret_id>', methods=['GET'])
@access_required
def view_secret(secret_id):
    confirmed = request.args.get('confirmed', 'false').lower() == 'true'
    
    if confirmed:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute(
                "SELECT encrypted_data FROM secrets WHERE id = ? AND expires_at >= datetime('now')",
                (secret_id,))
            result = cursor.fetchone()
            
            if not result:
                return render_template('view.html', error="Секрет не найден или истек")
            
            conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            decrypted = decrypt_data(result[0])
            return render_template('view.html', secret=decrypted)
    else:
        return render_template('confirm.html', secret_id=secret_id)

@app.route('/confirm/<secret_id>', methods=['POST'])
@access_required
def confirm_view(secret_id):
    return redirect(url_for('view_secret', secret_id=secret_id, confirmed='true'))

# Инициализация Flask-RESTx API после обычных роутов
api = Api(
    app,
    version='1.0',
    title='Secret Sharing API',
    description='API для безопасного обмена секретами',
    doc='/swagger/',
    default='Secrets',
    default_label='Операции с секретами',
    prefix='/api/v1'  # Changed from '/api' to '/api/v1'
)

# Модели для Swagger
secret_model = api.model('Secret', {
    'data': fields.String(required=True, description='Секретные данные для хранения'),
})

secret_response_model = api.model('SecretResponse', {
    'id': fields.String(description='Уникальный идентификатор секрета'),
    'url': fields.String(description='URL для доступа к секрету'),
})

secret_get_model = api.model('SecretGet', {
    'data': fields.String(description='Расшифрованные данные'),
})

# Namespace для API
ns = Namespace('secrets', description='Операции с секретами', path='/')
api.add_namespace(ns)

# API Endpoints
@ns.route('/secret')
class SecretCreate(Resource):
    @ns.expect(secret_model)
    @ns.marshal_with(secret_response_model, code=201)
    @ns.response(400, 'Неверный запрос')
    @ns.response(403, 'Доступ запрещен')
    def post(self):
        """Создать новый секрет"""
        data = api.payload.get('data')
        if not data:
            api.abort(400, "Поле data обязательно")
        
        secret_id = secrets.token_urlsafe(16)
        expires_at = datetime.now() + timedelta(days=1)
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO secrets (id, encrypted_data, expires_at) VALUES (?, ?, ?)",
                (secret_id, encrypt_data(data), expires_at)
            )
        
        return {
            "id": secret_id,
            "url": f"{request.host_url}view/{secret_id}"
        }, 201

@ns.route('/secret/<string:secret_id>')
class SecretGet(Resource):
    @ns.marshal_with(secret_get_model)
    @ns.response(404, 'Секрет не найден')
    @ns.response(403, 'Доступ запрещен')
    def get(self, secret_id):
        """Получить секрет по ID (одноразовый)"""
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute(
                "SELECT encrypted_data FROM secrets WHERE id = ? AND expires_at >= datetime('now')",
                (secret_id,)
            )
            result = cursor.fetchone()
            
            if not result:
                api.abort(404, "Секрет не найден или истек")
            
            conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            return {"data": decrypt_data(result[0])}

# Обработчики ошибок
@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Forbidden", "message": str(e.description)}), 403
    return render_template('403.html', message=e.description), 403

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Not found"}), 404
    return render_template('404.html'), 404

@app.route('/favicon.ico')
def favicon():
    return '', 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
