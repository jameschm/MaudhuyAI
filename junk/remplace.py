import csv

def count_allow_deny(file_path):
    allow_count = 0
    deny_count = 0

    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            target = row['target'].lower()
            if 'allow' in target:
                allow_count += 1
            if 'deny' in target:
                deny_count += 1

    return allow_count, deny_count

file_path = './data/matrice de flux/after/all_query_v2.csv'
allow_count, deny_count = count_allow_deny(file_path)
print(f"Nombre d'occurrences de 'allow' : {allow_count}")
print(f"Nombre d'occurrences de 'deny' : {deny_count}")