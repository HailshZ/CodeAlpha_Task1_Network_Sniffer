#!/usr/bin/env python3
"""
CodeAlpha Task 1: Network Sniffer (Version 3)
Author: Hailemariam Zeleke
Features: IPs, Ports, TCP Flags, SYN Scan Alert, and INTERFACE SELECTION.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def analyze_packet(packet):
    """Analyze and display packet details."""
    
    if IP not in packet:
        return
    
    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto
    
    # Protocol name mapping
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    proto_name = proto_map.get(proto, "Unknown")
    
    print(f"\n[+] {src_ip} → {dst_ip} | Protocol: {proto_name}")
    
    # TCP Packet
    if TCP in packet:
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.flags
        
        print(f"    TCP Ports: {sport} → {dport}")
        
        # Decode TCP Flags
        flag_parts = []
        if flags & 0x02:
            flag_parts.append("SYN")
        if flags & 0x10:
            flag_parts.append("ACK")
        if flags & 0x04:
            flag_parts.append("RST")
        if flags & 0x01:
            flag_parts.append("FIN")
        if flags & 0x08:
            flag_parts.append("PSH")
        if flags & 0x20:
            flag_parts.append("URG")
        
        if flag_parts:
            print(f"    Flags: {' '.join(flag_parts)}")
        else:
            print(f"    Flags: 0x{flags:02x}")
        
        # SYN Scan Detection (CRITICAL)
        if flags == 0x02:
            print("    ⚠️  SYN SCAN DETECTED!")
    
    # UDP Packet
    elif UDP in packet:
        udp = packet[UDP]
        print(f"    UDP Ports: {udp.sport} → {udp.dport}")
    
    # ICMP Packet
    elif ICMP in packet:
        icmp = packet[ICMP]
        if icmp.type == 8:
            print("    ICMP Echo Request (Ping)")
        elif icmp.type == 0:
            print("    ICMP Echo Reply (Pong)")

def main():
    # Get interface from command line argument
    interface = None
    if len(sys.argv) > 2 and sys.argv[1] == "-i":
        interface = sys.argv[2]
        print(f"\n[+] Listening on interface: {interface}")
    
    print("\n" + "="*60)
    print("   CODEALPHA NETWORK SNIFFER v3.0")
    print("   Author: Hailemariam Zeleke")
    print("="*60)
    print("\n[+] Capturing 15 packets... Press Ctrl+C to stop.\n")
    
    # Sniff with the specified interface
    sniff(iface=interface, prn=analyze_packet, count=15)
    
    print("\n[+] Capture complete.")

if __name__ == "__main__":
    main()