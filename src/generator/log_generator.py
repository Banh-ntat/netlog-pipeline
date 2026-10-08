import random
import socket
import time
from datetime import datetime, timezone

TARGET = ("127.0.0.1", 5514)

ROUTERS = ["R1", "R2", "R3-HCM", "R4-HN"]
SWITCHES = ["SW1", "SW2", "SW3-DN"]
FIREWALLS = ["FW-HCM-01", "FW-HN-01"]


def pri(facility: int, severity: int) -> int:
    return facility * 8 + severity


def ts() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%b ") + f"{now.day:2d}" + now.strftime(" %H:%M:%S")


def random_external_ip() -> str:
    return f"198.51.{random.randint(100, 199)}.{random.randint(1, 250)}"


def link_event(host):
    state = random.choice(["up", "down"])
    sev = 3 if state == "down" else 5
    intf = f"GigabitEthernet0/{random.randint(0, 24)}"
    return (f"<{pri(23, sev)}>{ts()} {host} %LINK-{sev}-UPDOWN: "
            f"Interface {intf}, changed state to {state}")


def login_failed(host):
    return (f"<{pri(23, 4)}>{ts()} {host} %SEC_LOGIN-4-LOGIN_FAILED: "
            f"Login failed [user: admin] [Source: {random_external_ip()}]")


def cpu_hog(host):
    return f"<{pri(23, 2)}>{ts()} {host} %SYS-2-CPUHOG: CPU utilization above 90 percent"


def ospf_change(host):
    return (f"<{pri(23, 5)}>{ts()} {host} %OSPF-5-ADJCHG: "
            f"Process 1, Nbr 10.0.0.{random.randint(2, 9)} on Gi0/0 from FULL to DOWN")


def fw_event(host):
    deny = random.random() < 0.3
    src = random_external_ip() if deny else f"10.0.1.{random.randint(2, 250)}"
    port = random.choice([22, 23, 3389, 445]) if deny else random.choice([53, 80, 443])
    action = "deny" if deny else "accept"
    return (f'<{pri(16, 6)}>devname="{host}" type=traffic action={action} '
            f"srcip={src} dstip=10.0.0.{random.randint(2, 50)} dstport={port} proto=6")


def normal_event():
    """Log nền: chủ yếu traffic bình thường, sự cố thật rất hiếm."""
    r = random.random()
    if r < 0.85:
        return fw_event(random.choice(FIREWALLS))
    if r < 0.93:
        return login_failed(random.choice(SWITCHES))
    if r < 0.997:
        return ospf_change(random.choice(ROUTERS))
    if r < 0.9999:
        return link_event(random.choice(ROUTERS + SWITCHES))
    return cpu_hog(random.choice(SWITCHES))


def scenario_flapping(sock, host="R1", intf="GigabitEthernet0/1", times=8):
    """Cổng chập chờn: up/down liên tục."""
    for i in range(times):
        state = "down" if i % 2 == 0 else "up"
        sev = 3 if state == "down" else 5
        msg = (f"<{pri(23, sev)}>{ts()} {host} %LINK-{sev}-UPDOWN: "
               f"Interface {intf}, changed state to {state}")
        sock.sendto(msg.encode(), TARGET)
        time.sleep(0.2)


def scenario_bruteforce(sock, src="203.0.113.50", times=40):
    """Dò quét: một IP bị firewall chặn hàng loạt."""
    for _ in range(times):
        msg = (f'<{pri(16, 6)}>devname="FW-HCM-01" type=traffic action=deny '
               f"srcip={src} dstip=10.0.0.5 dstport=22 proto=6")
        sock.sendto(msg.encode(), TARGET)
        time.sleep(0.05)


def scenario_login_bruteforce(sock, src="198.51.100.7", host="SW2", times=8):
    """Đoán mật khẩu: một IP đăng nhập sai nhiều lần vào một switch."""
    for _ in range(times):
        msg = (f"<{pri(23, 4)}>{ts()} {host} %SEC_LOGIN-4-LOGIN_FAILED: "
               f"Login failed [user: admin] [Source: {src}]")
        sock.sendto(msg.encode(), TARGET)
        time.sleep(0.2)


def main(eps: int = 50):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Gửi log tới {TARGET} với ~{eps} sự kiện/giây. Ctrl+C để dừng.")
    counter = 0
    while True:
        sock.sendto(normal_event().encode(), TARGET)
        counter += 1
        if counter % 2000 == 0:
            scenario_flapping(sock)
        if counter % 2500 == 0:
            scenario_login_bruteforce(sock)
        if counter % 3000 == 0:
            scenario_bruteforce(sock)
        time.sleep(1 / eps)


if __name__ == "__main__":
    main()