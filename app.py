import hashlib
import os
import sqlite3
import traceback
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
import cloudscraper
import requests
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__)
# Correction pour Railway (force HTTPS sur les redirections OAuth)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.environ.get("SECRET_KEY", "une_cle_secrete_par_defaut")

# --- CONFIGURATION OAUTH DISCORD ---
oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id=os.environ.get('DISCORD_CLIENT_ID'),
    client_secret=os.environ.get('DISCORD_CLIENT_SECRET'),
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/api/',
    client_kwargs={'scope': 'identify email'}
)

# --- CONFIGURATION API TIERS ---
BRIX_API_KEY = os.environ.get("BRIX_API_KEY", "brix_votre_cle_api")
VT_API_KEY = os.environ.get("VT_API_KEY", "votre_cle_virustotal")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "TON_WEBHOOK_DISCORD_ICI")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

BASE_URL = "https://api.brixhub.to/api/v1"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Création d'un scraper capable de contourner Cloudflare
scraper = cloudscraper.create_scraper()

# --- INITIALISATION DE LA BASE DE DONNÉES SQLITE ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            avatar TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_country_flag(country_code):
    if not country_code or len(country_code) != 2:
        return "🏳️"
    return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))

def get_ip_info(ip):
    try:
        if ip in ["127.0.0.1", "::1", "localhost", "10.0.2.15"]:
            return {"city": "Localhost", "country": "FR"}
            
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
            
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {"city": "Inconnue", "country": "XX"}

def send_discord_log(user_ip, query, result_count, user_agent):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "TON_WEBHOOK_DISCORD_ICI":
        return
    
    try:
        geo = get_ip_info(user_ip)
        city = geo.get("city", "Inconnue")
        country_code = geo.get("country", "XX")
        flag = get_country_flag(country_code)
        
        payload = {
            "embeds": [{
                "title": "🔍 Nouvelle recherche effectuée",
                "color": 5793266, 
                "fields": [
                    {"name": "Recherche", "value": f"`{query}`", "inline": False},
                    {"name": "Résultats", "value": f"📊 **{result_count}** trouvés", "inline": True},
                    {"name": "Localisation", "value": f"{flag} {city} ({country_code})", "inline": True},
                    {"name": "Adresse IP", "value": f"`{user_ip}`", "inline": True},
                    {"name": "User-Agent", "value": f"```{user_agent}```", "inline": False}
                ]
            }]
        }
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=2)
    except Exception as e:
        print("Erreur envoi log Discord:", str(e))

# --- ROUTES DE L'APPLICATION ET AUTHENTIFICATION ---

@app.route('/')
def index():
    return render_template('index.html', user=session)

@app.route('/login/discord')
def login_discord():
    redirect_uri = url_for('authorize_discord', _external=True)
    return discord.authorize_redirect(redirect_uri)

@app.route('/login/authorized')
def authorize_discord():
    try:
        token = discord.authorize_access_token()
        resp = discord.get('users/@me', token=token)
        user_info = resp.json()

        discord_id = str(user_info.get('id'))
        username = user_info.get('username')
        discriminator = user_info.get('discriminator')
        if discriminator and discriminator != '0':
            username = f"{username}#{discriminator}"
            
        email = user_info.get('email')
        avatar_id = user_info.get('avatar')
        avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_id}.png" if avatar_id else "https://cdn.discordapp.com/embed/avatars/0.png"

        # Enregistrement ou mise à jour en base de données SQLite
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (discord_id, username, email, avatar)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET
                username = excluded.username,
                email = excluded.email,
                avatar = excluded.avatar
        ''', (discord_id, username, email, avatar_url))
        conn.commit()
        conn.close()

        # Stockage dans la session Flask
        session['user_id'] = discord_id
        session['username'] = username
        session['avatar'] = avatar_url
        session['email'] = email

    except Exception as e:
        print("Erreur d'authentification OAuth:", str(e))

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- API RECHERCHE OSINT MULTICRITÈRE ---
@app.route('/search', methods=['GET'])
def search_data():
    try:
        params = {k: v for k, v in request.args.items() if v != ''}
        
        headers = {
            "Authorization": f"Bearer {BRIX_API_KEY}",
            "Accept": "application/json"
        }
        
        response = scraper.get(f"{BASE_URL}/search", params=params, headers=headers, timeout=20)
        
        if response.status_code != 200:
            print(f"Erreur API externe [{response.status_code}]: {response.text}")
            return jsonify({"status": "error", "message": f"Erreur API externe: {response.status_code}"}), 500
            
        data = response.json()
        
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        query_str = " / ".join([f"{k}={v}" for k, v in params.items() if k not in ['flexible', 'per_page']])
        result_count = len(data.get('results', [])) if isinstance(data, dict) else 0
        
        send_discord_log(user_ip, query_str, result_count, user_agent)
        
        return jsonify(data)
            
    except Exception as e:
        traceback.print_exc()  # Affiche la trace complète de l'erreur dans les logs Railway
        return jsonify({"status": "error", "message": str(e)}), 500

# --- API SCAN DE FICHIERS VIRUSTOTAL ---
@app.route('/scan-file', methods=['POST'])
def scan_file():
    try:
        body = request.get_json()
        file_hash = body.get('hash')
        
        if not file_hash:
            return jsonify({"status": "error", "message": "Empreinte SHA-256 manquante."}), 400
            
        headers = {
            "x-apikey": VT_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(f"{VT_URL}{file_hash}", headers=headers, timeout=12)
        
        if response.status_code == 200:
            vt_data = response.json()
            stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return jsonify({
                "status": "success",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0)
            })
        elif response.status_code == 404:
            return jsonify({
                "status": "not_found",
                "message": "Aucun rapport VirusTotal trouvé pour ce fichier."
            })
        else:
            return jsonify({"status": "error", "message": f"Erreur VirusTotal: {response.status_code}"}), 500
            
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
