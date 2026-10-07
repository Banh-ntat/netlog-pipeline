import os

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
RAW_TOPIC = os.getenv("RAW_TOPIC", "raw-logs")

UDP_HOST = os.getenv("UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.getenv("UDP_PORT", "5514"))

PG_DSN = os.getenv(
    "PG_DSN", "host=127.0.0.1 port=5433 dbname=netlog user=netlog password=netlog123"
)