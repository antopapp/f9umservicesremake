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

# MISE À JOUR DE L'URL OFFICIELLE (Vue sur la doc .ru)
BASE_URL = "https://api.brixhub.ru/api/v1"
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
            return {"city": "Localhost", "country": "FR", "org": "Réseau Local"}
            
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
            
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                "city": data.get("city", "Inconnue"),
                "country": data.get("country", "XX"),
                "org": data.get("org", "FAI Inconnu")
            }
    except Exception:
        pass
    return {"city": "Inconnue", "country": "XX", "org": "FAI Inconnu"}

def send_discord_log(user_ip, query, result_count, user_agent, user_session):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "TON_WEBHOOK_DISCORD_ICI":
        return
    
    try:
        geo = get_ip_info(user_ip)
        city = geo.get("city", "Inconnue")
        country_code = geo.get("country", "XX")
        isp_org = geo.get("org", "Inconnu")
        flag = get_country_flag(country_code)
        
        # Récupération des infos de l'utilisateur connecté s'il y en a
        user_id = user_session.get('user_id')
        username = user_session.get('username')
        avatar = user_session.get('avatar')
        
        # Configuration de l'auteur du webhook selon la connexion
        if user_id:
            author_name = f"{username} (ID: {user_id})"
            author_icon = avatar if avatar else "https://cdn.discordapp.com/embed/avatars/0.png"
        else:
            author_name = "Visiteur Non Connecté"
            author_icon = "https://cdn.discordapp.com/embed/avatars/0.png"

        payload = {
            "embeds": [{
                "title": "🔍 Nouvelle recherche effectuée",
                "color": 5793266, 
                "author": {
                    "name": author_name,
                    "icon_url": author_icon
                },
                "fields": [
                    {"name": "Recherche", "value": f"`{query}`", "inline": False},
                    {"name": "Résultats", "value": f"📊 **{result_count}** trouvés", "inline": True},
                    {"name": "Localisation", "value": f"{flag} {city} ({country_code})", "inline": True},
                    {"name": "FAI / Opérateur", "value": f"`{isp_org}`", "inline": True},
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

# --- API RECHERCHE OSINT MULTICRITÈRE (MODIFIÉE EN POST AVEC JSON) ---
@app.route('/search', methods=['GET'])
def search_data():
    try:
        # Récupération des paramètres sous forme de dictionnaire JSON pour le POST
        params = {k: v for k, v in request.args.items() if v != ''}
        
        headers = {
            "Authorization": f"Bearer {BRIX_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Passage en scraper.post avec json=params comme indiqué dans la doc officielle
        response = scraper.post(f"{BASE_URL}/search", json=params, headers=headers, timeout=20)
        
        if response.status_code != 200:
            print(f"Erreur API externe [{response.status_code}]: {response.text}")
            return jsonify({"status": "error", "message": f"Erreur API externe: {response.status_code}"}), 500
            
        data = response.json()
        
        # Correction pour récupérer uniquement la première IP propre (sans les proxys multiples)
        raw_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_ip = raw_ip.split(',')[0].strip() if raw_ip else request.remote_addr
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        query_str = " / ".join([f"{k}={v}" for k, v in params.items() if k not in ['flexible', 'per_page']])
        
        # Adaptation selon la structure de réponse documentée (resp['data']['results'] ou similaire)
        results_container = data.get('data', data)
        result_count = len(results_container.get('results', [])) if isinstance(results_container, dict) else 0
        
        # On passe la session de l'utilisateur à la fonction du webhook
        send_discord_log(user_ip, query_str, result_count, user_agent, session)
        
        return jsonify(data)
            
    except Exception as e:
        traceback.print_exc()
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
