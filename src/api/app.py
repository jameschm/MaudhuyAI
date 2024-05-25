from flask import Flask, request, jsonify
from flask_caching import Cache
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import logging

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Charger le modèle fine-tuné et le tokenizer
model_name = "./maudhuyAI/v2_2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

def clear_cache():
    """
    Effacer le cache au démarrage de l'application.
    """
    with app.app_context():
        cache.clear()
        logger.info("Cache cleared at startup.")

@cache.memoize()
def predict(texts):
    """
    Prédire les étiquettes pour les textes donnés en utilisant le modèle fine-tuné.

    Args:
    texts (list): Liste des textes à prédire.

    Returns:
    list: Liste des prédictions sous forme de chaînes 'allow' ou 'deny'.
    """
    inputs = tokenizer(texts, return_tensors="pt", truncation=True, padding=True, max_length=512)
    with torch.no_grad():
        logits = model(**inputs).logits
    predictions = torch.argmax(logits, dim=-1).tolist()
    return ['allow' if pred == 1 else 'deny' for pred in predictions]

@app.route('/predict', methods=['POST'])
def predict_route():
    """
    Route pour la prédiction des étiquettes.

    Returns:
    json: JSON contenant les prédictions.
    """
    data = request.json
    input_texts = data.get('input_text', [])
    if not input_texts:
        logger.error("No input_text provided")
        return jsonify({"error": "No input_text provided"}), 400

    predictions = predict(input_texts)
    logger.info(f"Predictions made: {predictions}")
    return jsonify({"predictions": predictions})

@app.route('/health', methods=['GET'])
def health_check():
    """
    Route pour vérifier la santé de l'API.

    Returns:
    json: JSON indiquant le statut de l'API.
    """
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    logger.info("Starting Flask API...")
    clear_cache()
    from waitress import serve
    serve(app, host="0.0.0.0", port=55555)
