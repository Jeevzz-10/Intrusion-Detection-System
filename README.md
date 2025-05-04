DoS Attack Detection using Python (IDS)<br>
This project simulates a basic Denial of Service (DoS) attack and demonstrates how an Intrusion Detection System (IDS) can detect abnormal SYN flood traffic using raw sockets in Python.

Project Structure
DoS_server.py – Runs the IDS (Intrusion Detection System) that monitors incoming TCP packets and detects SYN flood patterns.
DoS_attack_host.py – Simulates a DoS attack by sending a large number of SYN packets to a target.
README.md – Project explanation and usage instructions.

How It Works
The attacker script (DoS_attack_host.py) sends multiple fake TCP SYN packets to the victim.
The server script (DoS_server.py) captures TCP packets in real time using raw sockets.
If the IDS detects unusually high SYN requests from the same IP, it flags it as a potential SYN flood attack.

Requirements
Python 3.x
Admin/root privileges (required for raw socket access)
colorama library (for colored alerts in terminal)

Install required Python package:
pip install colorama

Usage
1. Start IDS server:
sudo python DoS_server.py
Provide how many TCP packets to capture when prompted.

2. Start attacker script from another system or VM:
python DoS_attack_host.py
Enter:
   Target IP (victim's IP)
   Target port (e.g., 80)
   Number of packets to send (e.g., 100)

Example Output

[*] IDS Initialized - Capturing only TCP packets
[*] Waiting to capture 50 TCP packets...

#1: 192.168.0.105:42424 → 192.168.0.106:80 [SYN]
#2: 192.168.0.105:42535 → 192.168.0.106:80 [SYN]
...

[ALERT] High SYN rate detected from 192.168.0.105! Possible SYN flood attack.

--- IDS TCP Packet Analysis Summary ---

IP: 192.168.0.105 (hostname.local)
    ↳ Total TCP Packets: 50
    ↳ Unique Ports Contacted: 1
    ↳ SYN Packets: 50
      CRITICAL (Definite SYN flood or attack!)

[*] Capture completed in 12.30 seconds.

What You Learn
Working with raw sockets in Python
Understanding TCP/IP headers
Building a basic packet sniffer
Detecting SYN flood DoS attacks
Using struct for binary data parsing

Disclaimer
This project is for educational purposes only. Do not use this code to attack any system without explicit permission.
