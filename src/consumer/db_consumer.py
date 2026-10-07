import json
import sys
import time

import psycopg2
from psycopg2.extras import execute_values
from confluent_kafka import Consumer, KafkaError

sys.path.append("src")
from common.config import KAFKA_BOOTSTRAP, RAW_TOPIC, PG_DSN
from common.parser import parse_message

BATCH_SIZE = 500
FLUSH_INTERVAL = 1.0  # giây

COLUMNS = [
    "event_time", "received_at", "device_name", "device_type", "source_ip",
    "facility", "severity", "severity_name", "category", "event_code",
    "message", "src_ip", "dst_ip", "dst_port", "action", "interface",
    "raw", "fingerprint",
]
INSERT_SQL = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES %s"


def flush(conn, events, unparsed):
    with conn.cursor() as cur:
        if events:
            rows = [tuple(e.get(c) for c in COLUMNS) for e in events]
            execute_values(cur, INSERT_SQL, rows, page_size=BATCH_SIZE)
        if unparsed:
            execute_values(
                cur,
                "INSERT INTO unparsed_logs (received_at, source_ip, raw) VALUES %s",
                unparsed,
            )
    conn.commit()


def main():
    conn = psycopg2.connect(PG_DSN)
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "db-writer",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,      # tự commit sau khi ghi DB thành công
    })
    consumer.subscribe([RAW_TOPIC])
    print("Consumer bắt đầu đọc...")

    events, unparsed = [], []
    last_flush = time.time()
    total = 0

    try:
        while True:
            msg = consumer.poll(0.5)
            if msg is not None:
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        print(f"[Kafka error] {msg.error()}")
                else:
                    try:
                        envelope = json.loads(msg.value())
                        ev = parse_message(envelope)
                        if ev:
                            events.append(ev)
                        else:
                            unparsed.append(
                                (envelope["received_at"], envelope.get("source_ip"), envelope.get("raw"))
                            )
                    except Exception as exc:
                        print(f"[Parse error] {exc}")

            size = len(events) + len(unparsed)
            if size and (size >= BATCH_SIZE or time.time() - last_flush >= FLUSH_INTERVAL):
                flush(conn, events, unparsed)
                consumer.commit(asynchronous=False)   # chỉ commit sau khi DB đã ghi xong
                total += size
                print(f"Đã ghi {size} dòng (tổng {total})")
                events.clear()
                unparsed.clear()
                last_flush = time.time()
            elif not size:
                last_flush = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
        conn.close()


if __name__ == "__main__":
    main()
