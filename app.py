import os
import requests
from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
import cloudscraper
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration pour Railway / Proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

BRIX_API_KEY = os.environ.get("BRIX_API_KEY", "brix_votre_cle_api")
VT_API_KEY = os.environ.get("VT_API_KEY", "votre_cle_virustotal")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "TON_WEBHOOK_DISCORD_ICI")

BASE_URL = "https://api.brixhub.to/api/v1"
VT_URL = "https://www.virustotal.com/api/v3/files/"

scraper = cloudscraper.create_scraper()

def get_country_flag(country_code):
    if not country_code or len(country_code) != 2 or country_code == "XX":
        return "🌐"
    return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))

def get_geo_from_ip(ip):
    """Géolocalise l'IP avec ip-api.com si aucune donnée n'est fournie par le frontend."""
    if not ip or ip in ["127.0.0.1", "::1", "localhost"]:
        return {"city": "Localhost / Inconnue", "country": "XX"}
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return {
                    "city": data.get("city", "Inconnue"),
                    "country": data.get("countryCode", "XX")
                }
    except Exception as e:
        print("Erreur géolocalisation IP:", str(e))
    return {"city": "Inconnue", "country": "XX"}

def send_discord_log(user_ip, query_details, result_count, city=None, country=None):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "TON_WEBHOOK_DISCORD_ICI":
        return

    try:
        # Résolution de la ville si elle est manquante
        if not city or city == "Inconnue":
            geo = get_geo_from_ip(user_ip)
            city = geo.get("city", "Inconnue")
            country = geo.get("country", "XX")

        flag = get_country_flag(country)

        payload = {
            "embeds": [
                {
                    "title": "🔍 Nouvelle recherche sur le site",
                    "color": 5793266,  # Vert
                    "fields": [
                        {
                            "name": "🔎 Recherche effectuée",
                            "value": f"```{query_details}```",
                            "inline": False,
                        },
                        {
                            "name": "📊 Résultats trouvés",
                            "value": f"**{result_count}** résultat(s)",
                            "inline": True,
                        },
                        {
                            "name": "📍 Localisation",
                            "value": f"{flag} {city} ({country})",
                            "inline": True,
                        },
                        {
                            "name": "🌐 Adresse IP",
                            "value": f"`{user_ip}`",
                            "inline": True,
                        },
                    ],
                }
            ]
        }
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        print("Erreur d'envoi au webhook Discord:", str(e))

# ==========================================
# Option A : Service des fichiers SEO statiques
# ==========================================
@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(app.static_folder, 'sitemap.xml')

# ==========================================
# Routes de l'application
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET'])
def search():
    # 1. Récupération de l'IP, Ville et Pays envoyés par le JS ou détectés
    client_ip = request.args.get('visitor_ip') or request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip().replace('::ffff:', '')

    client_city = request.args.get('visitor_city')
    client_country = request.args.get('visitor_country')

    # 2. On récupère les critères de recherche
    req_data = request.args.to_dict()

    # Liste des paramètres de télémétrie à ne pas envoyer à l'API BrixHub
    internal_keys = {'visitor_ip', 'visitor_city', 'visitor_country', 'client_ip', 'city', 'country', 'adresse_ip'}
    
    # Nettoyage pour garder uniquement la recherche réelle
    search_params = {
        k: v for k, v in req_data.items() 
        if v not in ['', None, 'tous'] and k not in internal_keys
    }

    # Préparation du texte lisible pour Discord
    if search_params:
        query_text = "\n".join([f"{k}: {v}" for k, v in search_params.items() if k not in ['flexible', 'per_page']])
    else:
        query_text = "Aucun critère spécifié"

    # Paramètres de recherche BrixHub
    payload_brix = dict(search_params)
    payload_brix['flexible'] = True
    try:
        payload_brix['per_page'] = int(payload_brix.get('per_page', 35))
    except ValueError:
        payload_brix['per_page'] = 35

    headers = {'X-API-Key': BRIX_API_KEY, 'Content-Type': 'application/json'}

    try:
        response = scraper.post(f'{BASE_URL}/search', json=payload_brix, headers=headers)
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

        labels = {
            "nom_famille": "Nom de famille", "prenom": "Prénom", "date_naissance": "Date de naissance",
            "annee_naissance": "Année de naissance", "ville_naissance": "Ville de naissance",
            "adresse": "Adresse", "ville": "Ville", "code_postal": "Code postal", "pays": "Pays",
            "genre": "Genre", "telephone": "Téléphone", "email": "E-mail", "iban": "IBAN", "bic": "BIC"
        }

        for item in items_list:
            if isinstance(item, dict):
                lignes_formatees = [
                    f"• {labels.get(k.lower(), k.replace('_', ' ').capitalize())} : {', '.join(map(str, v)) if isinstance(v, list) else v}"
                    for k, v in item.items() if not k.startswith("_")
                ]
                formatted_text = "\n".join(lignes_formatees)
            else:
                formatted_text = str(item)

            formatted_results.append({"data": formatted_text})

        # 3. Envoi du log lisible sur Discord
        result_count = len(formatted_results)
        send_discord_log(client_ip, query_text, result_count, client_city, client_country)

        return jsonify({"status": "success", "results": formatted_results}), response.status_code

    except Exception as e:
        print('Erreur lors de la recherche :', str(e))
        return jsonify({'status': 'error', 'message': str(e), 'results': []}), 500

@app.route('/scan-file', methods=['POST'])
def scan_file():
    file_hash = request.json.get('hash')
    if not file_hash:
        return jsonify({'status': 'error', 'message': 'Aucun hash fourni.'}), 400
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = scraper.get(f'{VT_URL}{file_hash}', headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return jsonify({'status': 'success', 'malicious': stats.get('malicious', 0)})
        return jsonify({'status': 'not_found'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
