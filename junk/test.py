import requests
import json

# URL de l'API
url = "http://localhost:55555/predict"

# Données à envoyer en JSON
data = {
    "input_text": "fe80::76ac:b9ff:fea5:f71f 43658 ff02::1 10001 UDP scp-config"
}

# Convertir le dictionnaire en JSON
data_json = json.dumps(data)

# Envoyer la requête POST
response = requests.post(url, data=data_json, headers={'Content-Type': 'application/json'})

# Afficher la réponse
print(response.json())