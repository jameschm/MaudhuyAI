import logging
import mysql.connector
import csv
import os

# Configurer la journalisation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurer la connexion à la base de données
db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'packet_analysis'
}

# Liste des ports à vérifier
ports = [
    22, 25, 53, 80, 88, 123, 135, 389, 443, 445, 993, 3268, 3268, 3268, 4343, 5222, 5222, 5722, 5722, 5985,
    5985, 6007, 6012, 6141, 6187, 7443, 7764, 8080, 9090, 15001, 15432, 17387, 21112, 41361, 41400, 46704,
    49154, 49211, 49212, 49216, 49217, 49811, 50066, 50077, 50636, 50888, 53119, 53155, 53166, 53175, 57066,
    60276, 60639, 60706, 60899, 63707, 63793
]

def count_ports_and_insert_false_positives(db_config, ports):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Compter le nombre de lignes dans new_data
        query_new_data_count = "SELECT COUNT(*) FROM new_data"
        cursor.execute(query_new_data_count)
        new_data_count = cursor.fetchone()[0]
        
        # Compter le nombre de lignes dans false_positive_frames
        query_false_positives_count = "SELECT COUNT(*) FROM false_positive_frames"
        cursor.execute(query_false_positives_count)
        false_positives_count = cursor.fetchone()[0]
        
        port_counts_deny = {}
        for port in ports:
            # Compter les paquets avec les ports spécifiés
            query_total = (f"SELECT COUNT(*) FROM new_data "
                           f"WHERE source_port = %s OR destination_port = %s")
            cursor.execute(query_total, (port, port))
            count_total = cursor.fetchone()[0]
            
            query_deny = (f"SELECT * FROM new_data "
                          f"WHERE (source_port = %s OR destination_port = %s) "
                          f"AND prediction = 'deny'")
            cursor.execute(query_deny, (port, port))
            deny_rows = cursor.fetchall()
            count_deny = len(deny_rows)
            
            port_counts_deny[port] = {'total': count_total, 'deny': count_deny}
            
            for row in deny_rows:
                row_id = row[0]  # assuming the first column is the unique identifier
                check_query = "SELECT COUNT(*) FROM false_positive_frames WHERE id = %s"
                cursor.execute(check_query, (row_id,))
                if cursor.fetchone()[0] == 0:
                    # Modify the row to change prediction to 'allow'
                    modified_row = list(row)
                    modified_row[modified_row.index('deny')] = 'allow'
                    
                    # Construct the INSERT query with modified prediction
                    placeholders = ', '.join(['%s'] * len(modified_row))
                    insert_query = f"INSERT INTO false_positive_frames VALUES ({placeholders})"
                    cursor.execute(insert_query, modified_row)
                    conn.commit()
        
        # Compter et traiter les paquets avec prediction 'allow' qui n'ont pas les ports spécifiés
        placeholders = ', '.join(['%s'] * len(ports))
        query_allow = (f"SELECT * FROM new_data "
                       f"WHERE prediction = 'allow' "
                       f"AND source_port NOT IN ({placeholders}) "
                       f"AND destination_port NOT IN ({placeholders})")
        cursor.execute(query_allow, ports + ports)
        allow_rows = cursor.fetchall()

        port_counts_allow = {port: {'total': 0, 'allow': 0} for port in ports}
        for row in allow_rows:
            row_id = row[0]  # assuming the first column is the unique identifier
            source_port = row[2]
            destination_port = row[4]
            if source_port not in ports and destination_port not in ports:
                for port in ports:
                    port_counts_allow[port]['total'] += 1
                port_counts_allow[port]['allow'] += 1
                check_query = "SELECT COUNT(*) FROM false_positive_frames WHERE id = %s"
                cursor.execute(check_query, (row_id,))
                if cursor.fetchone()[0] == 0:
                    # Modify the row to change prediction to 'deny'
                    modified_row = list(row)
                    modified_row[modified_row.index('allow')] = 'deny'
                    
                    # Construct the INSERT query with modified prediction
                    placeholders = ', '.join(['%s'] * len(modified_row))
                    insert_query = f"INSERT INTO false_positive_frames VALUES ({placeholders})"
                    cursor.execute(insert_query, modified_row)
                    conn.commit()
        
        print(f"Total des requêtes traitées: {new_data_count}")
        print(f"Total des faux positifs: {false_positives_count}")
        print(f"Poucentage de réussite: {(new_data_count - false_positives_count) / new_data_count:.2%}")

        cursor.close()
        conn.close()
        
        return port_counts_deny, port_counts_allow

    except mysql.connector.Error as err:
        logger.error(f"Erreur lors de la connexion ou de l'exécution de la requête: {err}")
        return {}, {}

if __name__ == "__main__":
    port_counts_deny, port_counts_allow = count_ports_and_insert_false_positives(db_config, ports)
    for port, counts in port_counts_deny.items():
        if counts['total'] > 0 and counts['deny'] > 0:
            print(f"Port {port}: {counts['total']} fois (dont {counts['deny']} avec 'deny') == {counts['deny'] / counts['total']:.2%} d'echec")
    for port, counts in port_counts_allow.items():
        if counts['total'] > 0 and counts['allow'] > 0:
            print(f"Port {port}: {counts['total']} fois (dont {counts['allow']} avec 'allow') == {counts['allow'] / counts['total']:.2%} d'echec")

    cnx = mysql.connector.connect(**db_config)
    cursor = cnx.cursor()

    query = "SELECT * FROM false_positive_frames"
    cursor.execute(query)

    column_names = [i[0] for i in cursor.description]

    for i, name in enumerate(column_names):
        if name == 'prediction':
            column_names[i] = 'target'

    rows = cursor.fetchall()

    id_index = column_names.index('id')
    del column_names[id_index]
    rows = [list(row) for row in rows]
    for row in rows:
        del row[id_index]

    rows = [['any' if value is None else value for value in row] for row in rows]

    with open('./data/matrice de flux/new/dtframe.csv', 'r', newline='') as f:
        reader = csv.reader(f)
        existing_rows = list(reader)
    
    with open('./data/matrice de flux/new/dtframe.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        for row in rows:
            if row not in existing_rows:
                writer.writerow(row)

    cursor.close()
    cnx.close()