#!/usr/bin/env python3
"""
CodeAlpha Task 1: Network Sniffer
Author: Hailemariam Zeleke
Version: 1.0 (Minimal)
Description: Captures and displays source/destination IPs.
"""

from scapy.all import sniff, IP

def packet_callback(packet):
    """Called for each captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src} → Destination: {ip_layer.dst}")

def main():
    print("\n[+] Starting Network Sniffer... Press Ctrl+C to stop.\n")
    # Capture 10 packets (count=10) to test
    sniff(prn=packet_callback, count=10)
    print("\n[+] Capture complete.")

if __name__ == "__main__":
    main()