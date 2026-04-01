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
# Permitimos CORS para que el frontend (en otro puerto o carpeta) pueda consultar
CORS(app)

# Configuración de la Base de Datos (PostgreSQL en Docker)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@db:5432/secure_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- GENERACIÓN DE CLAVE DE CIFRADO (Una sola vez para el server) ---
# En producción, esto debe ser una variable de entorno fija.
# Para este ejercicio, generamos una si no existe.
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"*** MANTENGA ESTA CLAVE SEGURA: {ENCRYPTION_KEY} ***")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# --- MODELO DE LA BASE DE DATOS (Mapeado del Diagrama) ---
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(80), primary_key=True)
    password_hash = db.Column(db.String(200), nullable=False)

class EncryptedRecord(db.Model):
    __tablename__ = 'encrypted_records'
    token = db.Column(db.String(36), primary_key=True)
    encrypted_content = db.Column(db.Text, nullable=False)
    # Relación con la tabla users
    owner_username = db.Column(db.String(80), db.ForeignKey('users.username'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'token': self.token,
            'owner': self.owner_username,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

# Inicializar la base de datos al arrancar
with app.app_context():
    db.create_all()

# --- RUTAS DE LA API (Mapeado del AppController) ---
@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.json
    username = data.get('username').lower()
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user:
        # Si no existe, lo creamos (Registro automático para la tarea)
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario creado y autenticado', 'username': username})
    
    # Si existe, verificamos la contraseña
    if check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login exitoso', 'username': username})
    else:
        return jsonify({'error': 'Contraseña incorrecta'}), 401

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    text = data.get('text')
    sername = data.get('username').lower() if data.get('username') else None

    if not text or not username:
        return jsonify({'error': 'Faltan datos'}), 400

    # 1. Cifrar el texto
    encrypted_text = cipher_suite.encrypt(text.encode()).decode()
    
    # 2. Generar Token Único
    unique_token = str(uuid.uuid4())

    # 3. Almacenar en la DB
    new_record = EncryptedRecord(
        token=unique_token,
        encrypted_content=encrypted_text,
        owner_username=username
    )
    db.session.add(new_record)
    db.session.commit()

    return jsonify({
        'token': unique_token,
        'message': 'Texto cifrado y almacenado correctamente.'
    })

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    data = request.json
    token = data.get('token')
    # Pedimos el username para verificar Quién está intentando descifrar,
    # aunque la regla dice que cualquiera con el token puede verlo,
    # pero el historial de INTENTOS debe registrar quién fue.
    # En esta versión simplificada, el historial es de "CREACIÓN", no de visualización.
    # Mostraremos quién CREÓ el registro asociado al token.

    if not token:
        return jsonify({'error': 'Token requerido'}), 400

    record = EncryptedRecord.query.filter_by(token=token).first()

    if not record:
        return jsonify({'error': 'Token no válido o no encontrado'}), 404

    try:
        # 1. Descifrar
        decrypted_text = cipher_suite.decrypt(record.encrypted_content.encode()).decode()
        
        # 2. Retornar datos originales y metadatos
        return jsonify({
            'original_text': decrypted_text,
            'owner': record.owner_username,
            'timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': 'Error al descifrar el contenido.'}), 500

@app.route('/api/history/<username>', methods=['GET'])
def get_history(username):
    # Convertimos el parámetro de la URL a minúsculas
    clean_username = username.lower()
    records = EncryptedRecord.query.filter_by(owner_username=clean_username).order_by(EncryptedRecord.timestamp.desc()).all()
    
    history_list = [record.to_dict() for record in records]
    return jsonify(history_list)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)