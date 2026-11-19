#!/usr/bin/env python3
"""
PCAP Attack Simulator
Generates a PCAP file with simulated network attacks + benign traffic
"""

from scapy.all import *
import random
import time

print("=" * 70)
print("  PCAP Attack Simulator")
print("  Generates realistic attack + benign traffic")
print("=" * 70)

# Configuration
OUTPUT_FILE = "simulated_attack.pcap"
TARGET_IP = "192.168.1.100"
ATTACKER_IP = "10.0.0.50"
BENIGN_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

packets = []

print("\n[1/6] Generating BENIGN traffic...")
# BENIGN - Normal HTTP requests
for i in range(50):
    src_ip = random.choice(BENIGN_IPS)
    # Normal HTTP GET request
    pkt = IP(src=src_ip, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(pkt)
    
    # Response
    pkt = IP(src=TARGET_IP, dst=src_ip) / TCP(sport=80, dport=random.randint(1024, 65535), flags="PA") / Raw(load="HTTP/1.1 200 OK\r\n\r\n")
    packets.append(pkt)
    
    time.sleep(0.001)

print(f"   ✓ Generated {len(packets)} benign packets")

print("\n[2/6] Generating DoS Hulk attack...")
# DoS Hulk - Rapid HTTP requests
dos_start = len(packets)
for i in range(100):
    # Flood of GET requests from same IP
    pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S") / Raw(load=f"GET /{random.randint(1000, 9999)} HTTP/1.1\r\n\r\n")
    packets.append(pkt)
print(f"   ✓ Generated {len(packets) - dos_start} DoS Hulk packets")

print("\n[3/6] Generating PortScan attack...")
# Port Scan - Sequential port probing
portscan_start = len(packets)
for port in range(20, 100):
    pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    packets.append(pkt)
print(f"   ✓ Generated {len(packets) - portscan_start} PortScan packets")

print("\n[4/6] Generating DDoS attack...")
# DDoS - Multiple source IPs attacking
ddos_start = len(packets)
for i in range(80):
    # Random source IPs (botnet)
    src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    pkt = IP(src=src_ip, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
    packets.append(pkt)
print(f"   ✓ Generated {len(packets) - ddos_start} DDoS packets")

print("\n[5/6] Generating SSH Brute Force (SSH-Patator)...")
# SSH Brute Force - Repeated SSH connection attempts
ssh_start = len(packets)
for i in range(30):
    pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=22, flags="S")
    packets.append(pkt)
    # Failed authentication (RST)
    pkt = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=22, dport=random.randint(1024, 65535), flags="R")
    packets.append(pkt)
print(f"   ✓ Generated {len(packets) - ssh_start} SSH-Patator packets")

print("\n[6/6] Generating Web Attack (SQL Injection attempts)...")
# Web Attack - SQL Injection attempts
web_start = len(packets)
sql_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--"
]
for payload in sql_payloads:
    for _ in range(5):
        pkt = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / Raw(load=f"GET /login?user={payload} HTTP/1.1\r\n\r\n")
        packets.append(pkt)
print(f"   ✓ Generated {len(packets) - web_start} Web Attack packets")

# Shuffle packets to make it more realistic
print("\n[*] Shuffling packets to simulate real network traffic...")
random.shuffle(packets)

# Write PCAP file
print(f"\n[*] Writing {len(packets)} packets to {OUTPUT_FILE}...")
wrpcap(OUTPUT_FILE, packets)

print("\n" + "=" * 70)
print("  ✓ PCAP file generated successfully!")
print("=" * 70)
print(f"\nFile: {OUTPUT_FILE}")
print(f"Total packets: {len(packets)}")
print(f"\nAttack breakdown:")
print(f"  • BENIGN:            ~100 packets (HTTP traffic)")
print(f"  • DoS Hulk:          ~100 packets (HTTP flood)")
print(f"  • PortScan:          ~80 packets (port probing)")
print(f"  • DDoS:              ~80 packets (distributed flood)")
print(f"  • SSH-Patator:       ~60 packets (SSH brute force)")
print(f"  • Web Attack - XSS:  ~25 packets (SQL injection)")
print("\nYou can now upload this PCAP file to the IDS dashboard!")
print("=" * 70)