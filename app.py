import hashlib
import os
import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import cloudscraper
import requests
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__)
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
        requests.post(DISCORD_WEBHOOK_URL, json=payload
