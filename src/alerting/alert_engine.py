import sys
import time

import psycopg2

sys.path.append("src")
from common.config import PG_DSN

INTERVAL = 30  # giây giữa các lần chạy


RULES = [
    {
        "name": "interface_flapping",
        "severity": "high",
        "bucket_seconds": 300,
        "sql": """
            SELECT device_name, interface AS entity, count(*) AS cnt,
                   min(event_time) AS w_start, max(event_time) AS w_end
            FROM events
            WHERE event_code LIKE 'LINK-%%UPDOWN'
              AND event_time > now() - interval '5 minutes'
              AND interface IS NOT NULL
            GROUP BY device_name, interface
            HAVING count(*) >= 5
        """,
        "desc": "Interface {entity} trên {device} chập chờn: {cnt} lần đổi trạng thái trong 5 phút",
    },
    {
        "name": "firewall_scan",
        "severity": "high",
        "bucket_seconds": 300,
        "sql": """
            SELECT device_name, host(src_ip) AS entity, count(*) AS cnt,
                   min(event_time) AS w_start, max(event_time) AS w_end
            FROM events
            WHERE category = 'traffic' AND action = 'deny'
              AND event_time > now() - interval '1 minute'
              AND src_ip IS NOT NULL
            GROUP BY device_name, src_ip
            HAVING count(*) >= 20
        """,
        "desc": "IP {entity} bị {device} chặn {cnt} lần trong 1 phút (nghi dò quét/tấn công)",
    },
    {
        "name": "critical_event",
        "severity": "critical",
        "bucket_seconds": 300,
        "sql": """
            SELECT device_name, event_code AS entity, count(*) AS cnt,
                   min(event_time) AS w_start, max(event_time) AS w_end
            FROM events
            WHERE severity <= 2
              AND event_time > now() - interval '1 minute'
            GROUP BY device_name, event_code
        """,
        "desc": "Thiết bị {device} ghi nhận sự kiện nghiêm trọng {entity} ({cnt} lần)",
    },
    {
        "name": "login_failed_repeated",
        "severity": "medium",
        "bucket_seconds": 300,
        "sql": """
            SELECT device_name, host(src_ip) AS entity, count(*) AS cnt,
                   min(event_time) AS w_start, max(event_time) AS w_end
            FROM events
            WHERE event_code LIKE 'SEC_LOGIN%%LOGIN_FAILED'
              AND event_time > now() - interval '5 minutes'
              AND src_ip IS NOT NULL
            GROUP BY device_name, src_ip
            HAVING count(*) >= 5
        """,
        "desc": "{cnt} lần đăng nhập thất bại vào {device} từ IP {entity} trong 5 phút",
    },
    {
        "name": "device_silent",
        "severity": "high",
        "bucket_seconds": 600,
        "sql": """
            SELECT device_name, device_name AS entity, 0 AS cnt,
                   max(event_time) AS w_start, max(event_time) AS w_end
            FROM events
            WHERE event_time > now() - interval '1 hour'
            GROUP BY device_name
            HAVING max(event_time) < now() - interval '5 minutes'
        """,
        "desc": "Thiết bị {device} không gửi log hơn 5 phút (có thể mất kết nối)",
    },
]

INSERT_ALERT = """
    INSERT INTO alerts (rule_name, severity, device_name, entity, description,
                        event_count, window_start, window_end, dedup_key)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (dedup_key) DO NOTHING
"""


def run_once(conn):
    created = 0
    bucket_now = int(time.time())
    with conn.cursor() as cur:
        for rule in RULES:
            cur.execute(rule["sql"])
            for device, entity, cnt, w_start, w_end in cur.fetchall():
                bucket = bucket_now // rule["bucket_seconds"]
                dedup_key = f"{rule['name']}|{device}|{entity}|{bucket}"
                desc = rule["desc"].format(device=device, entity=entity, cnt=cnt)
                cur.execute(INSERT_ALERT, (
                    rule["name"], rule["severity"], device, entity, desc,
                    cnt, w_start, w_end, dedup_key,
                ))
                created += cur.rowcount
    conn.commit()
    return created


def main():
    conn = psycopg2.connect(PG_DSN)
    print(f"Alert engine chạy mỗi {INTERVAL}s")
    while True:
        try:
            n = run_once(conn)
            if n:
                print(f"[{time.strftime('%H:%M:%S')}] Sinh {n} cảnh báo mới")
        except Exception as exc:
            conn.rollback()
            print(f"[ERROR] {exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
