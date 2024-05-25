import csv
import json

# Lire le fichier CSV existant et stocker les numéros de port existants
existing_ports = set()
with open('./data/matrice de flux/after/all_query_v2.csv', 'r') as csv_file:
    reader = csv.reader(csv_file, delimiter=';')
    next(reader)  # Skip the header
    for row in reader:
        if len(row) >= 5:  # Ensure there are at least 5 columns
            existing_ports.add(row[4])  # destination_port is the 5th column

# Lire le fichier JSON
with open('./data/ports/known_ports.json', 'r') as json_file:
    ports = json.load(json_file)

# Pour chaque entrée dans le JSON, vérifier si le numéro de port n'est pas déjà dans le CSV
with open('./data/matrice de flux/after/all_query_v2.csv', 'a', newline='') as csv_file:
    writer = csv.writer(csv_file, delimiter=';')
    for port_number, port_name in ports.items():
        if port_number not in existing_ports:
            # Si le numéro de port n'est pas dans le CSV, ajouter une nouvelle ligne avec les informations du port et "deny" comme cible
            writer.writerow(['any', 'any', 'any', 'any', port_number, 'tcp', port_name, 'deny'])
            writer.writerow(['any', 'any', 'any', 'any', port_number, 'udp', port_name, 'deny'])
            writer.writerow(['any', 'any', port_number, 'any', 'any', 'tcp', port_name, 'deny'])
            writer.writerow(['any', 'any', port_number, 'any', 'any', 'udp', port_name, 'deny'])