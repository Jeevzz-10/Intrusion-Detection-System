import socket
import struct
import time
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# Tracking structures
ip_counts = defaultdict(int)
ip_ports = defaultdict(set)
syn_counts = defaultdict(int)
hostname_cache = {}

# Hostname resolver with caching (to prevent slowdowns)
def resolve_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None
    hostname_cache[ip] = hostname
    return hostname

# Process and display a TCP packet
def parse_tcp_packet(packet, packet_num):
    ip_header = packet[0:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]

    if protocol != 6:  # Skip non-TCP packets
        return False

    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    tcp_header = packet[20:40]
    tcph = struct.unpack("!HHLLBBHHH", tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    flags = tcph[5]

    syn_flag = flags & 0x02 != 0  # SYN flag detection

    ip_counts[src_ip] += 1
    ip_ports[src_ip].add(dst_port)
    if syn_flag:
        syn_counts[src_ip] += 1

    # Lightweight logging for each packet
    print(f"#{packet_num}: {src_ip}:{src_port} → {dst_ip}:{dst_port} {'[SYN]' if syn_flag else ''}")

    # Real-time attack detection
    if syn_counts[src_ip] > 30:
        print(Fore.RED + f"[ALERT] High SYN rate detected from {src_ip}! Possible SYN flood attack.")

    return True  # TCP packet processed

# Summary after capture
def print_summary(start_time):
    print("\n--- IDS TCP Packet Analysis Summary ---")
    for ip in ip_counts:
        hostname = resolve_hostname(ip)
        count = ip_counts[ip]
        ports = ip_ports[ip]
        syns = syn_counts[ip]

        print(f"\nIP: {ip} ({hostname or 'N/A'})")
        print(f"    ↳ Total TCP Packets: {count}")
        print(f"    ↳ Unique Ports Contacted: {len(ports)}")
        print(f"    ↳ SYN Packets: {syns}")

        if syns <= 2:
            print(Fore.GREEN + "    Severity: Low (Normal traffic)")
        elif syns <= 10:
            print(Fore.YELLOW + "    Severity: Medium (Possible scan or probe)")
        elif syns <= 20:
            print(Fore.LIGHTRED_EX + "    Severity: High (Likely scan or SYN flood)")
        else:
            print(Fore.RED + "    Severity: CRITICAL (Definite SYN flood or attack!)")

    print(f"\n[*] Capture completed in {time.time() - start_time:.2f} seconds.")

# Main capture function
def run_ids(packet_limit):
    print("[*] IDS Initialized - Capturing only TCP packets")
    print(f"[*] Waiting to capture {packet_limit} TCP packets...\n")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("[-] Run as root (sudo) to use raw sockets.")
        return

    captured_tcp = 0
    start_time = time.time()

    while captured_tcp < packet_limit:
        try:
            raw_packet = s.recvfrom(65565)[0]
            if parse_tcp_packet(raw_packet, captured_tcp + 1):
                captured_tcp += 1
        except KeyboardInterrupt:
            print("\n[!] Capture interrupted by user.")
            break

    print_summary(start_time)

# Entry point
if __name__ == "__main__":
    try:
        limit = int(input("Enter number of TCP packets to capture: "))
        run_ids(limit)
    except ValueError:
        print("[-] Invalid number. Please enter a valid integer.")
