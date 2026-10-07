import json
import socket
import sys
from datetime import datetime, timezone

from confluent_kafka import Producer

sys.path.append("src")
from common.config import KAFKA_BOOTSTRAP, RAW_TOPIC, UDP_HOST, UDP_PORT

producer = Producer({
    "bootstrap.servers": KAFKA_BOOTSTRAP,
    "linger.ms": 20,               # gom message trong 20ms để gửi theo lô
    "compression.type": "lz4",
    "acks": "1",
})


def on_delivery(err, msg):
    if err is not None:
        print(f"[ERROR] gửi Kafka thất bại: {err}")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Tăng bộ đệm nhận để giảm rơi gói khi có đợt tăng đột biến
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((UDP_HOST, UDP_PORT))
    print(f"Collector lắng nghe UDP {UDP_HOST}:{UDP_PORT}")

    total = 0
    while True:
        data, addr = sock.recvfrom(8192)
        payload = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "source_ip": addr[0],
            "raw": data.decode("utf-8", errors="replace").strip(),
        }
        producer.produce(
            RAW_TOPIC,
            key=addr[0].encode(),               # cùng thiết bị → cùng partition → giữ thứ tự
            value=json.dumps(payload).encode(),
            on_delivery=on_delivery,
        )
        producer.poll(0)                        # phục vụ callback, không chặn
        total += 1
        if total % 1000 == 0:
            print(f"Đã nhận {total} gói")


if __name__ == "__main__":
    try:
        main()
    finally:
        producer.flush(5)
