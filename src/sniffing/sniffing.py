import logging
import queue
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import mysql.connector
import requests
from scapy.all import sniff, IP, IPv6, DNS, DNSQR, UDP, TCP
import threading
import hashlib

class ConfigLoader:
    @staticmethod
    def load_config(file_path):
        with open(file_path, 'r') as config_file:
            return json.load(config_file)

class LoggerSetup:
    @staticmethod
    def setup_logging(level):
        logging_level = getattr(logging, level.upper(), logging.INFO)
        logging.basicConfig(level=logging_level)
        logger = logging.getLogger(__name__)
        return logger

class DatabaseManager:
    def __init__(self, config):
        self.config = config['db_config']
        self.logger = LoggerSetup.setup_logging(config['logging_level'])

    def connect(self):
        try:
            return mysql.connector.connect(**self.config)
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de la connexion à la base de données: {err}")
            raise

    def database_exists(self):
        try:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES LIKE %s", (self.config['database'],))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result is not None
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de la vérification de l'existence de la base de données: {err}")
            return False

    def execute_sql_file(self, filepath):
        try:
            with open(filepath, 'r') as file:
                sql_commands = file.read()
            conn = self.connect()
            cursor = conn.cursor()
            for result in cursor.execute(sql_commands, multi=True):
                pass
            conn.commit()
            cursor.close()
            conn.close()
            self.logger.info("Base de données et tables créées avec succès.")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution du fichier SQL {filepath}: {e}")

    def get_all_tables(self, conn):
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            return [table[0] for table in cursor.fetchall()]

    def truncate_tables(self, conn, tables_to_keep):
        try:
            with conn.cursor() as cursor:
                tables = self.get_all_tables(conn)
                tables_to_truncate = [table for table in tables if table not in tables_to_keep]
                for table in tables_to_truncate:
                    cursor.execute(f"TRUNCATE TABLE {table}")
                self.logger.info("Tables effacées avec succès.")
                conn.commit()
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de l'effacement des tables: {err}")

    def insert_packets_batch(self, packet_details_list, table, include_prediction=True):
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                if include_prediction:
                    placeholders = ', '.join(['%s'] * len(packet_details_list[0]))
                    columns = ', '.join(packet_details_list[0].keys())
                else:
                    placeholders = ', '.join(['%s'] * (len(packet_details_list[0]) - 1))
                    columns = ', '.join([key for key in packet_details_list[0].keys() if key != 'prediction'])

                sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
                values = [
                    [value if value != 'none' else None for key, value in packet_details.items() if include_prediction or key != 'prediction']
                    for packet_details in packet_details_list
                ]
                cursor.executemany(sql, values)
                conn.commit()
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de l'insertion dans la table {table}: {err}")

    def load_known_ports(self):
        known_ports = {}
        try:
            conn = self.connect()
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT port, protocol FROM known_ports")
                known_ports = {str(row['port']): row['protocol'] for row in cursor.fetchall()}
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors du chargement des ports connus: {err}")
        self.logger.info("Ports connus chargés depuis la base de données")
        return known_ports

    def is_known_ports_table_empty(self):
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM known_ports")
                result = cursor.fetchone()
                return result[0] == 0
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de la vérification de la table known_ports: {err}")
            return True

class KnownPortsLoader:
    def __init__(self, config):
        self.known_ports_path = config['known_ports_path']
        self.logger = LoggerSetup.setup_logging(config['logging_level'])

    def load_known_ports(self):
        if os.path.isfile(self.known_ports_path):
            try:
                with open(self.known_ports_path, 'r') as f:
                    known_ports = json.load(f)
                self.logger.info(f"Ports connus chargés depuis {self.known_ports_path}")
                return known_ports
            except Exception as e:
                self.logger.error(f"Erreur lors du chargement des ports connus: {e}")
                return None
        else:
            self.logger.error(f"Fichier des ports connus introuvable à {self.known_ports_path}")
            return None

    def insert_known_ports(self, known_ports, db_manager):
        try:
            conn = db_manager.connect()
            cursor = conn.cursor()
            for port, protocol in known_ports.items():
                sql = "INSERT INTO known_ports (port, protocol) VALUES (%s, %s) ON DUPLICATE KEY UPDATE protocol = VALUES(protocol)"
                cursor.execute(sql, (port, protocol))
            conn.commit()
            cursor.close()
            conn.close()
            self.logger.info("Ports connus insérés dans la base de données")
        except mysql.connector.Error as err:
            self.logger.error(f"Erreur lors de l'insertion dans la base de données: {err}")
        except Exception as e:
            self.logger.error(f"Exception lors de l'insertion dans la base de données: {e}")

class PacketProcessor:
    def __init__(self, db_manager, config):
        self.db_manager = db_manager
        self.api_url = config['api_url']
        self.batch_size = config['batch_size']
        self.known_ports = db_manager.load_known_ports()
        self.packet_batch = []
        self.packet_queue = queue.Queue(maxsize=config['packet_queue_maxsize'])
        self.processed_packets_cache = set()
        self.api_cache = {}
        self.lock = threading.Lock()
        self.logger = LoggerSetup.setup_logging(config['logging_level'])

    def detect_protocol_l7(self, packet):
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet.sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet.dport if packet.haslayer(TCP) else packet[UDP].dport
            if str(sport) in self.known_ports:
                return self.known_ports[str(sport)]
            elif str(dport) in self.known_ports:
                return self.known_ports[str(dport)]
        return 'unknown'

    def process_packet(self, packet):
        try:
            protocol_l7 = self.detect_protocol_l7(packet)

            packet_details = {
                'domain': packet[DNSQR].qname.decode('utf-8').rstrip('.') if DNSQR in packet and packet.haslayer(DNS) else 'none',
                'source_ip': packet[IP].src if packet.haslayer(IP) else (packet[IPv6].src if packet.haslayer(IPv6) else 'none'),
                'source_port': packet[UDP].sport if packet.haslayer(UDP) else (packet[TCP].sport if packet.haslayer(TCP) else 'none'),
                'destination_ip': packet[IP].dst if packet.haslayer(IP) else (packet[IPv6].dst if packet.haslayer(IPv6) else 'none'),
                'destination_port': packet[UDP].dport if packet.haslayer(UDP) else (packet[TCP].dport if packet.haslayer(TCP) else 'none'),
                'protocol': 'TCP' if packet.haslayer(TCP) else ('UDP' if packet.haslayer(UDP) else 'none'),
                'application_layer_protocol': protocol_l7,
                'prediction': None
            }

            packet_hash = self.hash_packet(packet_details)
            
            with self.lock:
                if packet_hash not in self.processed_packets_cache:
                    self.processed_packets_cache.add(packet_hash)
                    self.packet_batch.append(packet_details)
                    if len(self.packet_batch) >= self.batch_size:
                        self.logger.info("Taille de lot atteinte, ajout des paquets à la file d'attente...")
                        self.packet_queue.put(self.packet_batch.copy())
                        self.packet_batch.clear()
        except Exception as e:
            self.logger.error(f"Erreur lors du traitement du paquet: {e}")

    def hash_packet(self, packet):
        packet_str = json.dumps(packet, sort_keys=True)
        return hashlib.md5(packet_str.encode('utf-8')).hexdigest()

    def send_packet_batch(self, session, packets):
        predictions = []

        for packet in packets:
            packet_hash = self.hash_packet(packet)
            if packet_hash in self.api_cache:
                predictions.append(self.api_cache[packet_hash])
            else:
                predictions.append(None)

        uncached_packets = [packet for packet, prediction in zip(packets, predictions) if prediction is None]
        if uncached_packets:
            uncached_input_texts = [f"{packet['domain']} {packet['source_ip']} {packet['source_port']} {packet['destination_ip']} {packet['destination_port']} {packet['protocol']} {packet['application_layer_protocol']}" for packet in uncached_packets]
            try:
                self.logger.info(f"Envoi de la requête à l'API avec cet input : {uncached_input_texts}")
                response = session.post(self.api_url, json={'input_text': uncached_input_texts})
                response.raise_for_status()
                results = response.json()
                self.logger.info(f"Résultats reçus de l'API: {results}")

                for packet, result in zip(uncached_packets, results.get('predictions', [])):
                    packet_hash = self.hash_packet(packet)
                    self.api_cache[packet_hash] = result
                    packet['prediction'] = result
            except requests.RequestException as e:
                self.logger.error(f"Erreur de requête lors de l'appel à l'API: {e}")

        for packet, prediction in zip(packets, predictions):
            if prediction is not None:
                packet['prediction'] = prediction

        self.db_manager.insert_packets_batch(packets, 'new_data')

        blocked_packets = [packet for packet in packets if packet['prediction'] == "deny"]
        passed_packets = [packet for packet in packets if packet['prediction'] != "deny"]

        if blocked_packets:
            self.db_manager.insert_packets_batch(blocked_packets, 'blocked_frames')
        if passed_packets:
            self.db_manager.insert_packets_batch(passed_packets, 'passed_frames')

    def send_packet_batches(self):
        session = requests.Session()
        while True:
            batch = self.packet_queue.get()
            if batch is None:
                break
            self.send_packet_batch(session, batch)

    def reset_caches(self):
        with self.lock:
            self.processed_packets_cache.clear()
            self.api_cache.clear()
        self.logger.info("Caches réinitialisés.")

class Sniffer:
    def __init__(self, packet_processor):
        self.packet_processor = packet_processor
        self.logger = LoggerSetup.setup_logging(config['logging_level'])

    def start_sniffing(self):
        self.logger.info("Démarrage de la capture du trafic réseau...")
        sniff(prn=self.packet_processor.process_packet, store=False)

class MainApp:
    def __init__(self, config):
        self.config = config
        self.logger = LoggerSetup.setup_logging(config['logging_level'])
        self.db_manager = DatabaseManager(config)
        self.known_ports_loader = KnownPortsLoader(config)
        self.packet_processor = PacketProcessor(self.db_manager, config)
        self.sniffer = Sniffer(self.packet_processor)

    def run(self):
        if not self.db_manager.database_exists():
            self.logger.info("La base de données n'existe pas, création de la base de données...")
            self.db_manager.execute_sql_file(config['sql_file_path'])

        if self.db_manager.is_known_ports_table_empty():
            self.logger.info("La table known_ports est vide, chargement des ports connus...")
            known_ports = self.known_ports_loader.load_known_ports()
            if known_ports:
                self.known_ports_loader.insert_known_ports(known_ports, self.db_manager)
        
        try:
            self.packet_processor.reset_caches()

            with self.db_manager.connect() as conn:
                tables_to_keep = self.config['tables_to_keep']
                self.db_manager.truncate_tables(conn, tables_to_keep)

            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(self.packet_processor.send_packet_batches), executor.submit(self.sniffer.start_sniffing)]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Erreur dans l'exécution du thread: {e}")
        except Exception as e:
            self.logger.error(f"Erreur dans la fonction principale: {e}")

if __name__ == "__main__":
    try:
        config = ConfigLoader.load_config('./src/sniffing/config.json')
        app = MainApp(config)
        app.run()
    except KeyboardInterrupt:
        logger = LoggerSetup.setup_logging('INFO')
        logger.info("Capture arrêtée par l'utilisateur")
