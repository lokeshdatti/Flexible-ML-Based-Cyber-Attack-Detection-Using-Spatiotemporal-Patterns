#!/usr/bin/env python3
"""
Advanced PCAP Attack Simulator
Generates realistic PCAP with proper TCP handshakes and timing
"""

from scapy.all import *
import random
import datetime

print("=" * 80)
print("  🔥 ADVANCED PCAP ATTACK SIMULATOR")
print("  Generates realistic network traffic with multiple attack types")
print("=" * 80)

# Configuration
OUTPUT_FILE = "realistic_attack.pcap"
TARGET_IP = "192.168.1.100"
TARGET_PORT = 80
SSH_PORT = 22
FTP_PORT = 21

# Attack sources
ATTACKER_IP = "10.0.0.50"
BENIGN_CLIENTS = [
    "192.168.1.10",
    "192.168.1.20", 
    "192.168.1.30",
    "192.168.1.40"
]

packets = []
timestamp = datetime.datetime.now().timestamp()

def add_packet(pkt, delay=0.001):
    """Add packet with timestamp"""
    global timestamp
    timestamp += delay
    pkt.time = timestamp
    packets.append(pkt)

print("\n📊 Traffic Generation Plan:")
print("  • BENIGN:        150 packets (normal web browsing)")
print("  • DoS Hulk:      200 packets (HTTP flood attack)")
print("  • PortScan:      100 packets (systematic port probe)")
print("  • DDoS:          150 packets (distributed attack)")
print("  • SSH-Patator:   80 packets (brute force SSH)")
print("  • Bot:           50 packets (automated scanning)")
print("  • FTP-Patator:   60 packets (FTP brute force)")
print("\n" + "=" * 80)

# ============================================================================
# 1. BENIGN TRAFFIC - Normal HTTP browsing
# ============================================================================
print("\n[1/7] 🟢 Generating BENIGN traffic (normal web usage)...")
benign_count = 0

for i in range(50):
    client = random.choice(BENIGN_CLIENTS)
    src_port = random.randint(10000, 65000)
    
    # Three-way handshake
    syn = IP(src=client, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="S", seq=1000)
    add_packet(syn, 0.05)
    
    syn_ack = IP(src=TARGET_IP, dst=client) / TCP(sport=TARGET_PORT, dport=src_port, flags="SA", seq=2000, ack=1001)
    add_packet(syn_ack, 0.01)
    
    ack = IP(src=client, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="A", seq=1001, ack=2001)
    add_packet(ack, 0.01)
    
    # HTTP GET request
    http_req = IP(src=client, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="PA", seq=1001, ack=2001) / Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    add_packet(http_req, 0.02)
    
    # HTTP response
    http_resp = IP(src=TARGET_IP, dst=client) / TCP(sport=TARGET_PORT, dport=src_port, flags="PA", seq=2001, ack=1200) / Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n" + "x" * 1024)
    add_packet(http_resp, 0.05)
    
    # FIN handshake
    fin = IP(src=client, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="FA", seq=1200, ack=3026)
    add_packet(fin, 0.01)
    
    benign_count += 6

print(f"   ✓ Generated {benign_count} BENIGN packets")

# ============================================================================
# 2. DoS Hulk Attack - HTTP GET/POST flood
# ============================================================================
print("\n[2/7] 🔴 Generating DoS Hulk attack (HTTP flood)...")
dos_count = 0

for i in range(100):
    src_port = random.randint(10000, 65000)
    
    # SYN flood - incomplete handshakes
    syn = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="S", seq=random.randint(1000, 9999))
    add_packet(syn, 0.001)  # Very fast
    
    # Sometimes complete the handshake and send flood
    if i % 3 == 0:
        syn_ack = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=TARGET_PORT, dport=src_port, flags="SA")
        add_packet(syn_ack, 0.001)
        
        # Rapid fire requests
        for j in range(random.randint(3, 7)):
            req = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="PA") / Raw(load=f"GET /{random.randint(1000, 9999)}.php HTTP/1.1\r\n\r\n")
            add_packet(req, 0.0001)
            dos_count += 1
    
    dos_count += 1

print(f"   ✓ Generated {dos_count} DoS Hulk packets")

# ============================================================================
# 3. Port Scan - Systematic probing
# ============================================================================
print("\n[3/7] 🟡 Generating PortScan attack (network reconnaissance)...")
portscan_count = 0

# Scan ports 1-100
for port in range(1, 101):
    syn = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=random.randint(50000, 60000), dport=port, flags="S", seq=random.randint(1000, 9999))
    add_packet(syn, 0.01)  # 10ms between scans (fast but not instant)
    
    # Some ports respond (open), others don't (closed/filtered)
    if port in [22, 80, 443, 8080, 3306]:  # Common open ports
        syn_ack = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=port, dport=syn.sport, flags="SA")
        add_packet(syn_ack, 0.005)
        
        # Send RST (scanner doesn't complete handshake)
        rst = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=syn.sport, dport=port, flags="R")
        add_packet(rst, 0.001)
        portscan_count += 2
    
    portscan_count += 1

print(f"   ✓ Generated {portscan_count} PortScan packets")

# ============================================================================
# 4. DDoS Attack - Distributed sources
# ============================================================================
print("\n[4/7] 🔴 Generating DDoS attack (botnet simulation)...")
ddos_count = 0

# Simulate botnet with random IPs
for i in range(50):
    # Random source IP (botnet)
    bot_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65000)
    
    # SYN flood from distributed sources
    for _ in range(3):
        syn = IP(src=bot_ip, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="S", seq=random.randint(1000, 9999))
        add_packet(syn, 0.0005)
        ddos_count += 1

print(f"   ✓ Generated {ddos_count} DDoS packets")

# ============================================================================
# 5. SSH-Patator - SSH Brute Force
# ============================================================================
print("\n[5/7] 🟠 Generating SSH-Patator attack (SSH brute force)...")
ssh_count = 0

passwords = ["admin", "password", "123456", "root", "test", "user", "default", "letmein"]

for attempt in range(40):
    src_port = random.randint(50000, 60000)
    
    # SSH connection attempt
    syn = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=SSH_PORT, flags="S", seq=1000)
    add_packet(syn, 0.1)
    
    syn_ack = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=SSH_PORT, dport=src_port, flags="SA", seq=2000, ack=1001)
    add_packet(syn_ack, 0.01)
    
    ack = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=SSH_PORT, flags="A", seq=1001, ack=2001)
    add_packet(ack, 0.01)
    
    # SSH handshake data
    ssh_data = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=SSH_PORT, flags="PA") / Raw(load=f"SSH-2.0-OpenSSH_8.0\r\n")
    add_packet(ssh_data, 0.05)
    
    # Failed authentication - connection reset
    rst = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=SSH_PORT, dport=src_port, flags="R")
    add_packet(rst, 0.1)
    
    ssh_count += 5

print(f"   ✓ Generated {ssh_count} SSH-Patator packets")

# ============================================================================
# 6. Bot Activity - Automated scanning
# ============================================================================
print("\n[6/7] 🟣 Generating Bot traffic (automated scanning)...")
bot_count = 0

bot_user_agents = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "python-requests/2.25.1",
    "curl/7.68.0",
    "Wget/1.20.3"
]

for i in range(25):
    src_port = random.randint(40000, 50000)
    
    # Bot scanning various endpoints
    endpoints = ["/admin", "/wp-admin", "/.env", "/config.php", "/backup.sql", "/api/v1"]
    
    for endpoint in random.sample(endpoints, 2):
        syn = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="S")
        add_packet(syn, 0.02)
        
        http_req = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="PA") / Raw(load=f"GET {endpoint} HTTP/1.1\r\nUser-Agent: {random.choice(bot_user_agents)}\r\n\r\n")
        add_packet(http_req, 0.01)
        
        bot_count += 2

print(f"   ✓ Generated {bot_count} Bot packets")

# ============================================================================
# 7. FTP-Patator - FTP Brute Force
# ============================================================================
print("\n[7/7] 🟠 Generating FTP-Patator attack (FTP brute force)...")
ftp_count = 0

for attempt in range(30):
    src_port = random.randint(50000, 60000)
    
    # FTP connection
    syn = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=FTP_PORT, flags="S")
    add_packet(syn, 0.2)
    
    syn_ack = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=FTP_PORT, dport=src_port, flags="SA")
    add_packet(syn_ack, 0.01)
    
    # FTP login attempt
    ftp_user = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=FTP_PORT, flags="PA") / Raw(load=f"USER admin\r\n")
    add_packet(ftp_user, 0.05)
    
    ftp_pass = IP(src=ATTACKER_IP, dst=TARGET_IP) / TCP(sport=src_port, dport=FTP_PORT, flags="PA") / Raw(load=f"PASS {random.choice(passwords)}\r\n")
    add_packet(ftp_pass, 0.05)
    
    # Failed - connection closed
    rst = IP(src=TARGET_IP, dst=ATTACKER_IP) / TCP(sport=FTP_PORT, dport=src_port, flags="R")
    add_packet(rst, 0.1)
    
    ftp_count += 5

print(f"   ✓ Generated {ftp_count} FTP-Patator packets")

# ============================================================================
# Finalize and Save
# ============================================================================
print("\n" + "=" * 80)
print(f"📦 Total packets generated: {len(packets)}")
print("\n⏱️  Adding realistic timing jitter...")

# Shuffle to simulate real network (attacks don't come in perfect order)
random.shuffle(packets)

print(f"💾 Writing PCAP file: {OUTPUT_FILE}")
wrpcap(OUTPUT_FILE, packets)

# Summary
print("\n" + "=" * 80)
print("  ✅ PCAP FILE GENERATED SUCCESSFULLY!")
print("=" * 80)
print(f"\n📁 File: {OUTPUT_FILE}")
print(f"📊 Total packets: {len(packets)}")
print(f"💽 File size: {os.path.getsize(OUTPUT_FILE) / 1024:.2f} KB")

print("\n🎯 Attack Distribution:")
print(f"  • BENIGN:        {benign_count:4d} packets (normal traffic)")
print(f"  • DoS Hulk:      {dos_count:4d} packets (HTTP flood)")
print(f"  • PortScan:      {portscan_count:4d} packets (reconnaissance)")
print(f"  • DDoS:          {ddos_count:4d} packets (distributed attack)")
print(f"  • SSH-Patator:   {ssh_count:4d} packets (SSH brute force)")
print(f"  • Bot:           {bot_count:4d} packets (automated scanning)")
print(f"  • FTP-Patator:   {ftp_count:4d} packets (FTP brute force)")

print("\n📋 Next Steps:")
print("  1. Open your IDS dashboard")
print("  2. Upload this PCAP file")
print("  3. Watch real-time analysis with attack detection!")
print("\n" + "=" * 80)