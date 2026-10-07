import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

SEVERITY_NAMES = [
    "emergency", "alert", "critical", "error",
    "warning", "notice", "informational", "debug",
]

# <PRI> rồi phần còn lại
RE_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)
# RFC 3164: "Oct  3 10:15:22 HOST rest..."
RE_3164 = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$", re.DOTALL)
# Cisco: %FACILITY-SEV-MNEMONIC: text
RE_CISCO = re.compile(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s*(.*)$")
RE_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
RE_INTF = re.compile(r"[Ii]nterface\s+(\S+?)[,\s]")
RE_SRC = re.compile(r"\[Source:\s*([\d.]+)\]")


def _parse_3164_time(text: str, fallback: datetime) -> datetime:
    """Log 3164 không có năm → dùng năm của thời điểm nhận."""
    try:
        t = datetime.strptime(f"{fallback.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
        return t.replace(tzinfo=fallback.tzinfo)
    except ValueError:
        return fallback


def _category_from_code(code: str) -> str:
    c = code.upper()
    if c.startswith(("LINK", "LINEPROTO")):
        return "link"
    if c.startswith(("SEC_LOGIN", "SSH", "AUTH")):
        return "auth"
    if c.startswith(("OSPF", "BGP", "EIGRP")):
        return "routing"
    if c.startswith("SYS"):
        return "system"
    return "other"


def _fingerprint(device: str, code: str, extra: str = "") -> str:
    return hashlib.sha1(f"{device}|{code}|{extra}".encode()).hexdigest()[:16]


def parse_message(envelope: dict) -> Optional[dict]:
    """
    envelope: {"received_at": iso, "source_ip": str, "raw": str}
    Trả về dict theo schema chuẩn, hoặc None nếu không phải log hợp lệ.
    """
    raw = envelope.get("raw", "")
    received_at = datetime.fromisoformat(envelope["received_at"])
    if received_at.tzinfo is None:
        received_at = received_at.replace(tzinfo=timezone.utc)

    m = RE_PRI.match(raw)
    if not m:
        return None
    pri = int(m.group(1))
    body = m.group(2)
    facility, severity = pri >> 3, pri & 7

    event = {
        "event_time": received_at,
        "received_at": received_at,
        "device_name": envelope.get("source_ip"),
        "device_type": "unknown",
        "source_ip": envelope.get("source_ip"),
        "facility": facility,
        "severity": severity,
        "severity_name": SEVERITY_NAMES[severity],
        "category": "other",
        "event_code": None,
        "message": body.strip(),
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "action": None,
        "interface": None,
        "raw": raw,
    }

    # ---- Trường hợp 1: key=value (firewall) ----
    if "devname=" in body and "action=" in body:
        kv = {k: v.strip('"') for k, v in RE_KV.findall(body)}
        event.update({
            "device_name": kv.get("devname", event["device_name"]),
            "device_type": "firewall",
            "category": "traffic",
            "event_code": f"FW-{kv.get('type', 'traffic').upper()}",
            "src_ip": kv.get("srcip"),
            "dst_ip": kv.get("dstip"),
            "dst_port": int(kv["dstport"]) if kv.get("dstport", "").isdigit() else None,
            "action": kv.get("action"),
        })
        event["fingerprint"] = _fingerprint(
            event["device_name"], event["event_code"], f"{event['action']}|{event['src_ip']}"
        )
        return event

        # ---- Trường hợp 2: RFC 3164 (router/switch/Linux) ----
    m2 = RE_3164.match(body)
    if m2:
        t = _parse_3164_time(m2.group(1), received_at)
        # Nếu giờ trong log lệch hơn 1 tiếng so với giờ nhận thì coi là không đáng tin
        if abs((t - received_at).total_seconds()) > 3600:
            t = received_at
        event["event_time"] = t
        event["device_name"] = m2.group(2)
        rest = m2.group(3)
        event["message"] = rest

        mc = RE_CISCO.search(rest)
        if mc:
            code = f"{mc.group(1)}-{mc.group(2)}-{mc.group(3)}"
            event["event_code"] = code
            event["category"] = _category_from_code(code)
            event["message"] = mc.group(4)
            event["device_type"] = "switch" if event["device_name"].upper().startswith("SW") else "router"
            mi = RE_INTF.search(rest)
            if mi:
                event["interface"] = mi.group(1)
            ms = RE_SRC.search(rest)
            if ms:
                event["src_ip"] = ms.group(1)
        else:
            # Log Linux/FRR: "bgpd[512]: neighbor ..."
            prog = rest.split(":", 1)[0].split("[")[0].strip()
            event["event_code"] = f"PROC-{prog.upper()}" if prog else None
            event["device_type"] = "router"
            event["category"] = "routing" if prog in ("bgpd", "ospfd", "zebra") else "system"

        event["fingerprint"] = _fingerprint(
            event["device_name"], event["event_code"] or "NA",
            event["interface"] or event["src_ip"] or "",
        )
        return event

    return None
