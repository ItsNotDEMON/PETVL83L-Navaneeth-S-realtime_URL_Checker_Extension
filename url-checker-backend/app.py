import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import datetime
import base64

app = Flask(__name__)
CORS(app)

cred = credentials.Certificate('firebase-key.json')  
firebase_admin.initialize_app(cred)
db = firestore.client()


API_KEY = '3fe3d372b1e99e493765786a52c64bcfda035c388225d0df0d01f8301237e596'  

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url_to_check = data.get('url')
    print("🌐 Received URL:", url_to_check)

    if not url_to_check:
        return jsonify({'error': 'URL not provided'}), 400

    headers = {
        "x-apikey": API_KEY
    }

    try:

        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code != 200:
            print("❌ VirusTotal API error:", response.text)
            return jsonify({'error': response.text}), 500

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        is_dangerous = malicious > 0 or suspicious > 0

        print("🛡️ Analysis:", {"malicious": malicious, "suspicious": suspicious})

        # Save to Firestore if URL is dangerous
        if is_dangerous:
            db.collection('malicious_urls').add({
                'url': url_to_check,
                'malicious': malicious,
                'suspicious': suspicious,
                'timestamp': datetime.datetime.utcnow().isoformat()
            })
            print("Saved to Firestore:", url_to_check)

        return jsonify({'dangerous': is_dangerous})

    except Exception as e:
        print("Backend error:", str(e))
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
