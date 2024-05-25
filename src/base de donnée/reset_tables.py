import mysql.connector
import logging

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

def connect_db():
    """
    Établir une connexion à la base de données.
    """
    return mysql.connector.connect(**DB_CONFIG)

def get_all_tables(conn):
    """
    Récupérer la liste de toutes les tables de la base de données.

    Args:
    conn: Connexion à la base de données.

    Returns:
    list: Liste des noms des tables.
    """
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = [table[0] for table in cursor.fetchall()]
    cursor.close()
    return tables

def truncate_tables(conn, tables_to_keep):
    """
    Effacer le contenu de toutes les tables sauf celles spécifiées.

    Args:
    conn: Connexion à la base de données.
    tables_to_keep (list): Liste des noms des tables à garder.
    """
    cursor = conn.cursor()
    try:
        tables = get_all_tables(conn)
        tables_to_truncate = [table for table in tables if table not in tables_to_keep]

        for table in tables_to_truncate:
            cursor.execute(f"TRUNCATE TABLE {table}")
            logger.info(f"Table {table} effacée")

        conn.commit()
    except mysql.connector.Error as err:
        logger.error(f"Erreur lors de l'effacement des tables: {err}")
    except Exception as e:
        logger.error(f"Exception lors de l'effacement des tables: {e}")
    finally:
        cursor.close()

def main():
    """
    Fonction principale pour effacer le contenu de toutes les tables sauf known_ports.
    """
    try:
        conn = connect_db()
        tables_to_keep = ['known_ports']
        truncate_tables(conn, tables_to_keep)
        conn.close()
    except mysql.connector.Error as err:
        logger.error(f"Erreur de connexion à la base de données: {err}")
    except Exception as e:
        logger.error(f"Exception dans la fonction principale: {e}")

if __name__ == "__main__":
    main()
