import hashlib
import os
from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
import cloudscraper
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration pour que Flask récupère correctement l'IP réelle sous Railway
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

BRIX_API_KEY = os.environ.get("BRIX_API_KEY", "brix_votre_cle_api")
VT_API_KEY = os.environ.get("VT_API_KEY", "votre_cle_virustotal")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "TON_WEBHOOK_DISCORD_ICI")
IPIFY_API_KEY = os.environ.get("IPIFY_API_KEY", "")

BASE_URL = "https://api.brixhub.to/api/v1"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Création d'un scraper capable de contourner Cloudflare
scraper = cloudscraper.create_scraper()

def get_country_flag(country_code):
    if not country_code or len(country_code) != 2:
        return "🏳️"
    return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))

def get_ipinfo_from_ipify(ip):
    """
    Interroge l'API ipify Geolocation (sans ipAddress si IP locale/inconnue,
    ou avec &ipAddress=... si l'IP est transmise).
    """
    if not IPIFY_API_KEY:
        return {"city": "Clé ipify manquante", "country": "XX"}

    try:
        # Si IP locale ou indéfinie, on laisse ipify détecter l'IP publique de la requête
        if ip in ["127.0.0.1", "::1", "localhost", "10.0.2.15"] or not ip:
            url = f"https://geo.ipify.org/api/v2/country,city?apiKey={IPIFY_API_KEY}"
        else:
            url = f"https://geo.ipify.org/api/v2/country,city?apiKey={IPIFY_API_KEY}&ipAddress={ip}"

        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            loc = data.get("location", {})
            return {
                "ip": data.get("ip", ip),
                "city": loc.get("city", "Inconnue"),
                "country": loc.get("country", "XX")
            }
    except Exception as e:
        print("Erreur ipify:", str(e))

    return {"ip": ip, "city": "Inconnue", "country": "XX"}

def send_discord_log(user_ip, query, result_count, user_agent, client_city=None, client_country=None):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "TON_WEBHOOK_DISCORD_ICI":
        return

    try:
        # Si la ville/pays sont déjà transmis par le client JS, on les utilise. Sinon, appel backend à ipify.
        if client_city and client_country:
            city = client_city
            country_code = client_country
            display_ip = user_ip
        else:
            geo_info = get_ipinfo_from_ipify(user_ip)
            city = geo_info.get("city", "Inconnue")
            country_code = geo_info.get("country", "XX")
            display_ip = geo_info.get("ip", user_ip)

        flag = get_country_flag(country_code)

        payload = {
            "embeds": [
                {
                    "title": "🔍 Nouvelle recherche effectuée",
                    "color": 5793266, # Vert épuré
                    "fields": [
                        {
                            "name": "Recherche",
                            "value": f"`{query}`",
                            "inline": False,
                        },
                        {
                            "name": "Résultats",
                            "value": f"📊 **{result_count}** trouvés",
                            "inline": True,
                        },
                        {
                            "name": "Localisation",
                            "value": f"{flag} {city} ({country_code})",
                            "inline": True,
                        },
                        {
                            "name": "Adresse IP",
                            "value": f"`{display_ip}`",
                            "inline": True,
                        },
                        {
                            "name": "User-Agent",
                            "value": f"```{user_agent}```",
                            "inline": False,
                        },
                    ],
                }
            ]
        }
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=2)
    except Exception as e:
        print("Erreur envoi log Discord:", str(e))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET'])
def search():
    # 1. On vérifie si une IP ou une localisation a été transmise directement depuis le client frontend
    override_ip = request.args.get('client_ip')
    client_city = request.args.get('city')
    client_country = request.args.get('country')

    if override_ip and override_ip.strip():
        user_ip = override_ip.strip()
    else:
        # Récupère l'IP détectée par le serveur
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if user_ip:
            user_ip = user_ip.split(',')[0].strip()
            if user_ip.startswith('::ffff:'):
                user_ip = user_ip.replace('::ffff:', '')
        
    user_agent = request.headers.get('User-Agent', 'Inconnu')

    # Récupère tous les paramètres de l'URL envoyés par le JS
    req_data = request.args.to_dict()

    # Nettoyage : on supprime tous les champs vides, "tous" ou nos paramètres internes d'IP
    cleaned_data = {
        k: v for k, v in req_data.items() 
        if v not in ['', None, 'tous', 'client_ip', 'city', 'country']
    }

    # Conversion du paramètre flexible en booléen si présent
    if 'flexible' in cleaned_data:
        cleaned_data['flexible'] = str(cleaned_data['flexible']).lower() == 'true'

    # Pagination fixée à 35 par défaut
    try:
        cleaned_data['per_page'] = int(cleaned_data.get('per_page', 35))
    except ValueError:
        cleaned_data['per_page'] = 35

    cleaned_data.setdefault('flexible', True)

    print('PAYLOAD NETTOYÉ ENVOYÉ À BRIXHUB :', cleaned_data)

    headers = {'X-API-Key': BRIX_API_KEY, 'Content-Type': 'application/json'}

    try:
        response = scraper.post(
            f'{BASE_URL}/search', json=cleaned_data, headers=headers
        )

        print('Réponse BrixHub status:', response.status_code)
        print('Réponse BrixHub body:', response.text)

        raw_json = response.json()

        formatted_results = []
        
        items_list = []
        if isinstance(raw_json, dict):
            if "data" in raw_json and isinstance(raw_json["data"], dict) and "results" in raw_json["data"]:
                items_list = raw_json["data"]["results"]
            elif "results" in raw_json:
                items_list = raw_json["results"]
            elif "data" in raw_json and isinstance(raw_json["data"], list):
                items_list = raw_json["data"]

        # On extrait la valeur principale recherchée pour l'afficher proprement dans le log Discord
        search_query_display = cleaned_data.get('query') or str(list(cleaned_data.values()))

        # Dictionnaire complet pour transformer les clés techniques en libellés propres
        labels = {
            "nom_famille": "Nom de famille",
            "prenom": "Prénom",
            "date_naissance": "Date de naissance",
            "annee_naissance": "Année de naissance",
            "ville_naissance": "Ville de naissance",
            "adresse": "Adresse",
            "ville": "Ville",
            "code_postal": "Code postal",
            "pays": "Pays",
            "genre": "Genre",
            "telephone": "Téléphone",
            "email": "E-mail",
            "iban": "IBAN",
            "bic": "BIC"
        }

        for item in items_list:
            if isinstance(item, dict):
                lignes_formatees = []
                for k, v in item.items():
                    if k.startswith("_"):
                        continue
                    
                    k_lower = k.lower()
                    nom_propre = labels.get(k_lower, k.replace("_", " ").capitalize())
                    
                    if isinstance(v, list):
                        valeur_propre = ", ".join(map(str, v))
                    else:
                        valeur_propre = str(v)
                        
                    lignes_formatees.append(f"• {nom_propre} : {valeur_propre}")
                
                formatted_text = "\n".join(lignes_formatees)
            else:
                formatted_text = str(item)

            formatted_results.append({"data": formatted_text})

        # Envoi direct du log sur Discord avec les informations de géolocalisation ipify
        result_count = len(formatted_results)
        send_discord_log(user_ip, search_query_display, result_count, user_agent, client_city, client_country)

        final_response = {
            "status": "success",
            "results": formatted_results
        }

        return jsonify(final_response), response.status_code

    except Exception as e:
        print('ERREUR PYTHON CAPTURÉE :', str(e))
        return jsonify({'status': 'error', 'message': str(e), 'results': []}), 500

@app.route('/scan-file', methods=['POST'])
def scan_file():
    file_hash = request.json.get('hash')

    if not file_hash:
        return jsonify({'status': 'error', 'message': 'Aucun hash fourni.'}), 400

    headers = {'x-apikey': VT_API_KEY}

    try:
        response = scraper.get(f'{VT_URL}{file_hash}', headers=headers)
        print('Réponse VirusTotal status:', response.status_code)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return jsonify({
                'status': 'success',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0)
            })
        elif response.status_code == 404:
            return jsonify({
                'status': 'not_found',
                'message': 'Fichier inconnu des bases de VirusTotal.'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Erreur lors de la communication avec l’API VirusTotal.'
            })

    except Exception as e:
        print('ERREUR VIRUSTOTAL CAPTURÉE :', str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/lookup/<lookup_type>/<path:value>', methods=['GET'])
def lookup(lookup_type, value):
    headers = {
        "X-API-Key": BRIX_API_KEY,
        "Content-Type": "application/json"
    }
    try:
        response = scraper.get(f"{BASE_URL}/lookup/{lookup_type}/{value}", headers=headers)
        try:
            return jsonify(response.json()), response.status_code
        except Exception:
            return jsonify({
                "status": "error", 
                "message": f"Réponse invalide (Statut {response.status_code})", 
                "raw_response": response.text
            }, response.status_code)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "data": None}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
