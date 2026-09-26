#!/usr/bin/env python3
"""
CodeAlpha Task 1: Network Packet Sniffer with Port-Scan Detection (v4.0)
Author: Hailemariam Zeleke
GitHub: https://github.com/HailshZ/CodeAlpha_Task1_Network_Sniffer

Features:
- Packet capture with interface selection (-i)
- TCP/UDP/ICMP protocol decoding
- TCP flag detection (SYN, ACK, RST, FIN, PSH, URG)
- HTTP payload extraction (Deep Packet Inspection)
- SYN scan detection with threshold (10 ports in 5 seconds)
- Protocol statistics summary
- Automatic file logging (logs/ folder with timestamp)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import sys
import time
import datetime
import os

# ==================== CONFIGURATION ====================
SYN_THRESHOLD = 10      # Number of ports to trigger a scan alert
SYN_WINDOW = 5          # Time window in seconds

# ==================== LOGGING SETUP ====================
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_filename = f"{LOG_DIR}/sniffer_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
log_file = open(log_filename, "w")
log_file.write("=" * 60 + "\n")
log_file.write("CODEALPHA NETWORK SNIFFER v4.0\n")
log_file.write(f"Started: {datetime.datetime.now()}\n")
log_file.write("=" * 60 + "\n")

# ==================== GLOBAL VARIABLES ====================
syn_counter = {}
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
packet_count = 0


# ==================== PACKET ANALYSIS FUNCTION ====================
def analyze_packet(packet):
    global packet_count
    packet_count += 1

    if IP not in packet:
        return

    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto

    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    proto_name = proto_map.get(proto, "Other")
    stats[proto_name] = stats.get(proto_name, 0) + 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    output_lines = []

    # --- Print and log packet info ---
    line = f"[{timestamp}] {src_ip} → {dst_ip} | {proto_name}"
    print(line)
    output_lines.append(line)

    # --- TCP Packet ---
    if TCP in packet:
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.flags

        tcp_info = f"    TCP Ports: {sport} → {dport}"
        print(tcp_info)
        output_lines.append(tcp_info)

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

        flag_str = " ".join(flag_parts) if flag_parts else f"0x{flags:02x}"
        flag_line = f"    Flags: {flag_str}"
        print(flag_line)
        output_lines.append(flag_line)

        # --- SYN Scan Detection (Threshold-based) ---
        if flags == 0x02:  # SYN only
            current_time = time.time()
            if src_ip not in syn_counter:
                syn_counter[src_ip] = []
            syn_counter[src_ip].append((current_time, dport))

            # Clean old entries (older than SYN_WINDOW seconds)
            syn_counter[src_ip] = [(t, p) for t, p in syn_counter[src_ip]
                                   if current_time - t <= SYN_WINDOW]

            unique_ports = set(p for t, p in syn_counter[src_ip])
            if len(unique_ports) >= SYN_THRESHOLD:
                alert_line = (f"    🚨🚨🚨 HIGH ALERT: Port scan from {src_ip}! "
                              f"({len(unique_ports)} ports in {SYN_WINDOW}s)")
                print(alert_line)
                output_lines.append(alert_line)
                log_file.write("=" * 60 + "\n")
                log_file.write(f"🚨 ALERT: Port scan from {src_ip} at {timestamp}\n")
                log_file.write(f"   {len(unique_ports)} ports scanned in {SYN_WINDOW}s\n")
                log_file.write("=" * 60 + "\n")

    # --- UDP Packet ---
    elif UDP in packet:
        udp = packet[UDP]
        udp_info = f"    UDP Ports: {udp.sport} → {udp.dport}"
        print(udp_info)
        output_lines.append(udp_info)

    # --- ICMP Packet ---
    elif ICMP in packet:
        icmp = packet[ICMP]
        icmp_type = icmp.type
        type_names = {8: "Echo Request (Ping)", 0: "Echo Reply (Pong)"}
        icmp_name = type_names.get(icmp_type, f"Type {icmp_type}")
        icmp_line = f"    ICMP: {icmp_name}"
        print(icmp_line)
        output_lines.append(icmp_line)

    # --- Payload Extraction (Deep Packet Inspection) ---
    if Raw in packet:
        raw_data = packet[Raw].load
        try:
            text = raw_data.decode('utf-8', errors='ignore')
            if text.strip():
                preview = text[:200].replace('\n', ' ').replace('\r', '')
                payload_line = f"    📄 Payload (first 200 chars): {preview}..."
                print(payload_line)
                output_lines.append(payload_line)
        except:
            payload_line = f"    📄 Payload (binary, {len(raw_data)} bytes)"
            print(payload_line)
            output_lines.append(payload_line)

    # --- Write to log file ---
    for line in output_lines:
        log_file.write(line + "\n")
    log_file.write("-" * 40 + "\n")
    print("-" * 40)


# ==================== MAIN FUNCTION ====================
def main():
    interface = None
    if len(sys.argv) > 2 and sys.argv[1] == "-i":
        interface = sys.argv[2]
        print(f"\n[+] Listening on interface: {interface}")

    print("\n" + "=" * 60)
    print("   CODEALPHA NETWORK SNIFFER v4.0")
    print("   Author: Hailemariam Zeleke")
    print("=" * 60)
    print(f"\n[+] Logging to: {log_filename}")
    print("\n[+] Capturing 30 packets... Press Ctrl+C to stop.\n")

    sniff(iface=interface, prn=analyze_packet, count=30)

    # ==================== CAPTURE SUMMARY ====================
    print("\n" + "=" * 60)
    print("   📊 CAPTURE SUMMARY")
    print("=" * 60)
    total = sum(stats.values())
    print(f"   Total Packets: {total}")
    for proto, count in stats.items():
        if count > 0:
            pct = (count / total * 100) if total > 0 else 0
            print(f"   {proto}: {count} ({pct:.1f}%)")
    print("=" * 60)

    log_file.write("\n" + "=" * 60 + "\n")
    log_file.write("CAPTURE SUMMARY\n")
    log_file.write(f"Total Packets: {total}\n")
    for proto, count in stats.items():
        if count > 0:
            log_file.write(f"{proto}: {count}\n")
    log_file.write("=" * 60 + "\n")
    log_file.close()

    print(f"\n[+] Log saved to: {log_filename}")


if __name__ == "__main__":
    main()
