import pandas as pd
from sklearn.model_selection import train_test_split
from datasets import Dataset

# Charger votre CSV dans un DataFrame
try:
    data = pd.read_csv('./data/matrice de flux/new/dtframe.csv')
except FileNotFoundError:
    raise FileNotFoundError("Le fichier CSV n'a pas été trouvé.")
except pd.errors.EmptyDataError:
    raise ValueError("Le fichier CSV est vide.")
except pd.errors.ParserError:
    raise ValueError("Erreur de parsing du fichier CSV.")

# Vérifiez que toutes les colonnes nécessaires sont présentes
required_columns = ['domain', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'application_layer_protocol', 'target']
for col in required_columns:
    if col not in data.columns:
        raise ValueError(f"Colonne manquante dans les données : {col}")

# Validation des données
if data[required_columns].isnull().values.any():
    raise ValueError("Certaines colonnes nécessaires contiennent des valeurs manquantes.")

# Remapper les étiquettes
valid_targets = {'allow', 'deny'}
if not set(data['target']).issubset(valid_targets):
    raise ValueError("Les étiquettes doivent être 'allow' ou 'deny'.")

# Vérification des ports
def is_valid_port(port):
    if port == 'any':
        return True
    try:
        port = int(port)
        return 0 <= port <= 65535
    except ValueError:
        return False

if not all(data['source_port'].apply(is_valid_port)) or not all(data['destination_port'].apply(is_valid_port)):
    raise ValueError("Les ports doivent être dans la plage 0-65535 ou 'any'.")

# Combiner les colonnes de flux en une seule chaîne de texte et mapper les étiquettes
input_texts = data.apply(lambda row: f"{row['domain']} {row['source_ip']} {row['source_port']} {row['destination_ip']} {row['destination_port']} {row['protocol']} {row['application_layer_protocol']}", axis=1)
labels = data['target'].map({'allow': 1, 'deny': 0})

# Créer un DataFrame avec les colonnes text et label
formatted_data = pd.DataFrame({
    'text': input_texts,
    'label': labels
})

# Diviser les données en jeux d'entraînement et de validation (80% formation, 20% validation)
train_df, test_df = train_test_split(formatted_data, test_size=0.2, random_state=42, stratify=formatted_data['label'])

# Charger les données dans le format attendu par Hugging Face Dataset
train_dataset = Dataset.from_pandas(train_df)
test_dataset = Dataset.from_pandas(test_df)

# Enregistrer les datasets au format Hugging Face
train_dataset.save_to_disk('./data/datasets/v2_3/train_dataset')
test_dataset.save_to_disk('./data/datasets/v2_3/test_dataset')

print("Les données de formation et de validation sont prêtes et enregistrées.")
