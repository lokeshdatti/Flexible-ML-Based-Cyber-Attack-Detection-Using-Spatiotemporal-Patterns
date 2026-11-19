from scapy.all import *
import random
import time

pcap_file = "voip_sample.pcap"
packets = []

src_ip = "192.168.1.10"
dst_ip = "192.168.1.20"

sip_sport = 5060
sip_dport = 5060
rtp_sport = 4000
rtp_dport = 4002

# -------- SIP INVITE --------
sip_invite = (
    "INVITE sip:user@192.168.1.20 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    "From: <sip:caller@192.168.1.10>\r\n"
    "To: <sip:user@192.168.1.20>\r\n"
    "Call-ID: 123456789\r\n"
    "CSeq: 1 INVITE\r\n\r\n"
)

pkt1 = IP(src=src_ip, dst=dst_ip)/UDP(sport=sip_sport, dport=sip_dport)/Raw(load=sip_invite)
packets.append(pkt1)

# -------- SIP OK --------
sip_ok = (
    "SIP/2.0 200 OK\r\n"
    "Via: SIP/2.0/UDP 192.168.1.10:5060\r\n"
    "From: <sip:caller@192.168.1.10>\r\n"
    "To: <sip:user@192.168.1.20>\r\n"
    "Call-ID: 123456789\r\n"
    "CSeq: 1 INVITE\r\n\r\n"
)

pkt2 = IP(src=dst_ip, dst=src_ip)/UDP(sport=sip_dport, dport=sip_sport)/Raw(load=sip_ok)
packets.append(pkt2)

# -------- RTP STREAM (fake audio payload) --------
for i in range(50):
    payload = bytes([random.randint(0,255) for _ in range(160)])

    # Basic RTP header (12 bytes)
    rtp_header = bytes([
        0x80, 0x00,              # Version / payload type
        (i >> 8) & 0xFF, i & 0xFF,  # Sequence
        0x00,0x00,0x00,i,        # Timestamp
        0x12,0x34,0x56,0x78      # SSRC
    ])

    rtp_pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=rtp_sport, dport=rtp_dport)/Raw(load=rtp_header+payload)
    packets.append(rtp_pkt)

for i in range(500):
    pkt = IP(src="10.0.0."+str(i%250+1),
             dst="192.168.1.20")/UDP(dport=80)/Raw(load="X"*10)
    packets.append(pkt)

# -------- Write PCAP --------
wrpcap(pcap_file, packets)
print("PCAP generated:", pcap_file)
