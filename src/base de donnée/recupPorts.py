import json
import mysql.connector
import logging
import os

# Configurer la journalisation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Définir les paramètres de la base de données
DB_CONFIG = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'packet_analysis'
}

# Chemin du fichier JSON
KNOWN_PORTS_PATH = './data/ports/known_ports.json'

def connect_db():
    """
    Établir une connexion à la base de données.
    """
    return mysql.connector.connect(**DB_CONFIG)

def load_known_ports():
    """
    Charger les ports connus et leurs protocoles à partir d'un fichier JSON.
    """
    if os.path.isfile(KNOWN_PORTS_PATH):
        try:
            with open(KNOWN_PORTS_PATH, 'r') as f:
                known_ports = json.load(f)
            logger.info(f"Ports connus chargés depuis {KNOWN_PORTS_PATH}")
            return known_ports
        except Exception as e:
            logger.error(f"Erreur lors du chargement des ports connus: {e}")
            return None
    else:
        logger.error(f"Fichier des ports connus introuvable à {KNOWN_PORTS_PATH}")
        return None

def insert_known_ports(known_ports):
    """
    Insérer les ports connus dans la base de données.

    Args:
    known_ports (dict): Dictionnaire contenant les ports connus et leurs protocoles.
    """
    try:
        conn = connect_db()
        cursor = conn.cursor()

        # Préparer l'insertion des données
        for port, protocol in known_ports.items():
            sql = "INSERT INTO known_ports (port, protocol) VALUES (%s, %s) ON DUPLICATE KEY UPDATE protocol = VALUES(protocol)"
            cursor.execute(sql, (port, protocol))

        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Ports connus insérés dans la base de données")
    except mysql.connector.Error as err:
        logger.error(f"Erreur lors de l'insertion dans la base de données: {err}")
    except Exception as e:
        logger.error(f"Exception lors de l'insertion dans la base de données: {e}")

def main():
    """
    Fonction principale pour charger les ports connus depuis le fichier JSON et les insérer dans la base de données.
    """
    known_ports = load_known_ports()
    if known_ports:
        insert_known_ports(known_ports)

if __name__ == "__main__":
    main()
