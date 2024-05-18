from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client import OAuthError
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Usa una variable de entorno para la clave secreta

# Configuración de MongoDB Atlas
mongo_uri = os.getenv('MONGO_URI', 'mongodb+srv://Carlos:Charlie23@cluster0.ivbpsns.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
client = MongoClient(mongo_uri)
db = client['Cluster0']
users = db['Carlos']
form_data = db['basedatosprimaria']  # Colección para los datos del formulario

# Configuración de Auth0
app.config['AUTH0_CLIENT_ID'] = os.getenv('AUTH0_CLIENT_ID', '1WGOEuIK1A2HYOtWUuMm3Ox7NQtFy9oK')
app.config['AUTH0_CLIENT_SECRET'] = os.getenv('AUTH0_CLIENT_SECRET', 'cGKU3t14ODIU7XvzOE7H4F06GGfdtlWqxgLIwhZ4vGo30aOs648fLJRAOsARPrfT')
app.config['AUTH0_DOMAIN'] = os.getenv('AUTH0_DOMAIN', 'dev-8r4jrhwww3gpjeet.us.auth0.com')
app.config['AUTH0_BASE_URL'] = f"https://{app.config['AUTH0_DOMAIN']}"
app.config['AUTH0_CALLBACK_URL'] = os.getenv('AUTH0_CALLBACK_URL', 'http://localhost:5000/callback')
app.config['AUTH0_AUDIENCE'] = f"https://{app.config['AUTH0_DOMAIN']}/userinfo"

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=app.config['AUTH0_CLIENT_ID'],
    client_secret=app.config['AUTH0_CLIENT_SECRET'],
    api_base_url=app.config['AUTH0_BASE_URL'],
    access_token_url=f"{app.config['AUTH0_BASE_URL']}/oauth/token",
    authorize_url=f"{app.config['AUTH0_BASE_URL']}/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f"https://{app.config['AUTH0_DOMAIN']}/.well-known/openid-configuration"
)

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=app.config['AUTH0_CALLBACK_URL'])

@app.route('/callback')
def callback():
    try:
        token = auth0.authorize_access_token()
        resp = auth0.get('userinfo')
        userinfo = resp.json()

        session['user'] = userinfo
        return redirect('/dashboard')
    except OAuthError as e:
        logging.error(f"OAuth error: {str(e)}")
        return str(e), 400

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    if user:
        return render_template('index.html', user=user)
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        auth0.api_base_url
        + '/v2/logout?returnTo='
        + url_for('home', _external=True)
        + '&client_id='
        + app.config['AUTH0_CLIENT_ID']
    )

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if email and password:
        logging.debug(f"Intentando registrar al usuario con correo electrónico: {email}")
        # Verifica si el usuario ya existe
        if users.find_one({"email": email}):
            logging.debug(f"Usuario con {email} ya existe")
            return jsonify({"msg": "El usuario ya existe"}), 400

        # Hashea la contraseña y guarda el usuario en MongoDB
        hashed_password = generate_password_hash(password)
        user = {
            "email": email,
            "password": hashed_password
        }
        result = users.insert_one(user)
        logging.debug(f"Usuario con {email} registrado exitosamente con el id: {result.inserted_id}")
        return jsonify({"msg": "Usuario registrado exitosamente"}), 201
    logging.debug("Invalid data received for signup")
    return jsonify({"msg": "Dato invalido"}), 400

@app.route('/custom-login', methods=['POST'])
def custom_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if email and password:
        logging.debug(f"Intentando iniciar sesión como usuario con correo electrónico: {email}")
        # Busca el usuario en MongoDB
        user = users.find_one({"email": email})
        if user and check_password_hash(user['password'], password):
            logging.debug(f"Usuario con el {email} iniciado exitosamente")
            # Aquí podrías generar un token o establecer la sesión
            session['user'] = {
                "email": user['email']
            }
            return jsonify({"msg": "Sesión iniciada correctamente"}), 200
        logging.debug(f"credenciales inválidas para el: {email}")
        return jsonify({"msg": "Credenciales inválidas"}), 401
    logging.debug("Dato no válido para iniciar sesión")
    return jsonify({"msg": "Dato inválido"}), 400

# Ruta para manejar el formulario
@app.route('/submit_form', methods=['POST'])
def submit_form():
    edad = request.form.get('edad')
    escolaridad = request.form.get('escolaridad')
    habilidades = request.form.get('habilidades')
    hobbies = request.form.get('hobbies')

    if edad and escolaridad and hobbies:
        form_entry = {
            "edad": edad,
            "escolaridad": escolaridad,
            "habilidades": habilidades,
            "hobbies": hobbies
        }
        form_data.insert_one(form_entry)
        return redirect(url_for('nosotros'))
    return jsonify({"msg": "Datos inválidos"}), 400

# Rutas adicionales
@app.route('/nosotros')
def nosotros():
    return render_template('single.html')

@app.route('/contacto')
def contacto():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)
