import os
from transformers import AutoModelForSequenceClassification, Trainer, TrainingArguments, AutoTokenizer
from datasets import load_from_disk, load_metric
import numpy as np
import torch

# Définissez votre Hugging Face Token comme une variable d'environnement
os.environ['HUGGINGFACE_TOKEN'] = #HF API KEY

# Vérifiez si des GPUs sont disponibles
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Utilisation du dispositif : {device}")

# Charger les datasets enregistrés à l'étape précédente
try:
    train_dataset = load_from_disk('./data/datasets/v2_3/train_dataset')
    test_dataset = load_from_disk('./data/datasets/v2_3/test_dataset')
except FileNotFoundError:
    raise FileNotFoundError("Les datasets enregistrés n'ont pas été trouvés.")

# Définir le nom du modèle pré-entrainé à utiliser
model_name = "./src/api/maudhuyAI/v2_2"

# Charger le tokenizer et le modèle
try:
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_auth_token=os.environ['HUGGINGFACE_TOKEN'])
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2, use_auth_token=os.environ['HUGGINGFACE_TOKEN'])
except Exception as e:
    raise RuntimeError(f"Erreur de chargement du modèle ou du tokenizer: {e}")

def tokenize_function(examples):
    return tokenizer(examples["text"], padding="max_length", truncation=True)

# Tokeniser les datasets
train_dataset = train_dataset.map(tokenize_function, batched=True)
test_dataset = test_dataset.map(tokenize_function, batched=True)

# Charger les datasets dans les formats nécessaires pour le modèle
train_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
test_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])

# Définir les métriques d'évaluation
metric = load_metric("accuracy")

def compute_metrics(p):
    preds = np.argmax(p.predictions, axis=1)
    return metric.compute(predictions=preds, references=p.label_ids)

# Arguments pour l'entraînement
training_args = TrainingArguments(
    output_dir='./results/v2_3',          
    evaluation_strategy="epoch",
    learning_rate=5e-5,
    per_device_train_batch_size=32, 
    per_device_eval_batch_size=32,
    num_train_epochs=4,
    weight_decay=0.01, 
    gradient_accumulation_steps=2,  
)

# Initialiser le Trainer
trainer = Trainer(
    model=model.to(device),
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    tokenizer=tokenizer,
    compute_metrics=compute_metrics
)

# Entraîner le modèle
trainer.train()

# Sauvegarder le modèle et le tokenizer
tokenizer.save_pretrained('./src/api/maudhuyAI/v2_3')
model.save_pretrained('./src/api/maudhuyAI/v2_3')

# Évaluer le modèle
eval_results = trainer.evaluate()
print(eval_results)
