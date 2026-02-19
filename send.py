#!/usr/bin/env python3
from scapy.all import *

load_contrib('erspan')

import time

# Konfiguration der Interfaces und Parameter
IFACE = "aci"
SESSION_ID = 123
SRC_IP = "10.10.0.150"
DST_IP = "10.10.3.150"

def create_packet():
    # Wir erzeugen einen großen Payload, um die 9000 Bytes zu füllen
    # 9000 - Ethernet(14) - IP(20) - TCP(20) = 8946 Bytes Payload
    payload = "A" * 8900

    packet = Ether(src="00:aa:bb:cc:dd:ee", dst="00:ff:ee:dd:cc:bb") / \
             IP(src="1.1.1.1", dst="2.2.2.2") / \
             TCP(sport=54321, dport=443) / payload
    return packet

def create_erspan_packet(session_id, src_ip, dst_ip):

    original_packet = create_packet()

    # 2. GRE-Header mit Key (Session ID)
    # Der 'key' im GRE-Header wird oft für die Zuordnung genutzt
    gre_header = GRE(proto=0x88be, key_present=1, key=123, seqnum_present=1, sequence_number=1, chksum_present=1)

    # 3. ERSPAN-Header (Typ II)
    # 'ver=1' entspricht ERSPAN Typ II
    erspan_header = ERSPAN(vlan=0, index=1, ver=1, session_id=SESSION_ID)

    # Paket zusammensetzen
    packet = Ether(src="00:11:22:33:44:55", dst="00:55:77:88:99") / IP(src=src_ip, dst=dst_ip) / gre_header / erspan_header / original_packet

    return packet

erspan_packet = create_erspan_packet(SESSION_ID, SRC_IP, DST_IP)
# Struktur anzeigen
erspan_packet.show2()

while True:
        sendp(erspan_packet, iface=IFACE, verbose=False)
        print(f"Paket über {IFACE} gesendet.")
        time.sleep(1)

