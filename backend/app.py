import os
import uuid
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
# Permitimos CORS para que el frontend local pueda consultar a la API en Docker
CORS(app)

# Configuración de la Base de Datos (PostgreSQL en Docker)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@db:5432/secure_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- CONFIGURACIÓN DE CIFRADO ---
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # Genera una llave nueva si no existe en el entorno
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"*** CLAVE GENERADA: {ENCRYPTION_KEY} ***")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# --- MODELOS DE DATOS (Relacionales) ---

class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(80), primary_key=True)
    password_hash = db.Column(db.String(200), nullable=False)
    # Relación para facilitar consultas desde el objeto user (opcional)
    records = db.relationship('EncryptedRecord', backref='owner', lazy=True)

class EncryptedRecord(db.Model):
    __tablename__ = 'encrypted_records'
    token = db.Column(db.String(36), primary_key=True)
    encrypted_content = db.Column(db.Text, nullable=False)
    # Llave foránea que vincula el registro con un usuario existente
    owner_username = db.Column(db.String(80), db.ForeignKey('users.username'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'token': self.token,
            'owner': self.owner_username,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

# Crear tablas si no existen al iniciar
with app.app_context():
    db.create_all()

# --- RUTAS DE LA API ---

@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.json
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Usuario y contraseña requeridos'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        # REGISTRO AUTOMÁTICO: Si no existe, lo creamos
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario registrado y autenticado', 'username': username}), 201
    
    # LOGIN: Si existe, verificamos hash
    if check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login exitoso', 'username': username}), 200
    else:
        return jsonify({'error': 'Contraseña incorrecta'}), 401

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    text = data.get('text')
    username = data.get('username', '').strip().lower()

    if not text or not username:
        return jsonify({'error': 'Faltan datos (texto o usuario)'}), 400

    # Verificar que el usuario exista (Integridad referencial)
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Usuario no autorizado'}), 401

    try:
        # 1. Cifrar
        encrypted_text = cipher_suite.encrypt(text.encode()).decode()
        
        # 2. Generar Token
        unique_token = str(uuid.uuid4())

        # 3. Guardar
        new_record = EncryptedRecord(
            token=unique_token,
            encrypted_content=encrypted_text,
            owner_username=username
        )
        db.session.add(new_record)
        db.session.commit()

        return jsonify({
            'token': unique_token,
            'message': 'Cifrado exitoso'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error interno al procesar el cifrado'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    data = request.json
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'error': 'Token requerido'}), 400

    record = EncryptedRecord.query.filter_by(token=token).first()

    if not record:
        return jsonify({'error': 'Token no válido o no encontrado'}), 404

    try:
        # Descifrar usando la misma suite
        decrypted_text = cipher_suite.decrypt(record.encrypted_content.encode()).decode()
        
        return jsonify({
            'original_text': decrypted_text,
            'owner': record.owner_username,
            'timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    except Exception:
        return jsonify({'error': 'No se pudo descifrar el contenido'}), 500

@app.route('/api/history/<username>', methods=['GET'])
def get_history(username):
    clean_username = username.strip().lower()
    
    # Obtenemos los registros ordenados por el más reciente
    records = EncryptedRecord.query.filter_by(owner_username=clean_username).order_by(EncryptedRecord.timestamp.desc()).all()
    
    return jsonify([r.to_dict() for r in records]), 200

if __name__ == '__main__':
    # El host 0.0.0.0 es necesario para que Docker escuche peticiones externas
    app.run(host='0.0.0.0', port=5000)