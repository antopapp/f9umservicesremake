import hashlib
import os
from flask import Flask, render_template, request, jsonify
import cloudscraper
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

BRIX_API_KEY = os.environ.get("BRIX_API_KEY", "brix_votre_cle_api")
VT_API_KEY = os.environ.get("VT_API_KEY", "votre_cle_virustotal")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "TON_WEBHOOK_DISCORD_ICI")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

BASE_URL = "https://api.brixhub.to/api/v1"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Création d'un scraper capable de contourner Cloudflare
scraper = cloudscraper.create_scraper()

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
                "color": 5793266, # Vert épuré
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET'])
def search():
    # Récupère l'IP réelle de l'utilisateur (prend en compte les proxies/reverse proxies)
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()
        
    user_agent = request.headers.get('User-Agent', 'Inconnu')

    # Récupère tous les paramètres de l'URL envoyés par le JS
    req_data = request.args.to_dict()

    # Nettoyage : on supprime tous les champs vides ou "tous"
    cleaned_data = {
        k: v for k, v in req_data.items() if v not in ['', None, 'tous']
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

        # Envoi asynchrone / direct du log sur Discord avec le nombre de résultats trouvés
        result_count = len(formatted_results)
        send_discord_log(user_ip, search_query_display, result_count, user_agent)

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
    app.run(debug=True, port=5000)