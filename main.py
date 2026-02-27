# full_firewall_pipeline.py
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import time
import json

# ----- Config -----
TIME_WINDOW = 5  # seconds
LOG_FILE = "firewall_logs.json"

# Store raw packets temporarily
packet_buffer = []

# ----- Packet Logger -----
def packet_logger(packet):
    if IP in packet:
        entry = {
            "timestamp": int(time.time()),
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
            "packet_size": len(packet),
            "tcp_flags": str(packet[TCP].flags) if TCP in packet else ""
        }
        packet_buffer.append(entry)
        print(f"Captured: {entry['source_ip']} -> {entry['destination_ip']} | {entry['protocol']} | Size: {entry['packet_size']}")

# ----- Feature Extractor -----
def extract_features(buffer):
    """
    Aggregates packets per source_ip in the last TIME_WINDOW
    """
    features = []
    current_time = int(time.time())
    window_start = current_time - TIME_WINDOW

    # Group packets by source_ip
    ip_packets = defaultdict(list)
    for pkt in buffer:
        if pkt['timestamp'] >= window_start:
            ip_packets[pkt['source_ip']].append(pkt)

    for src_ip, pkts in ip_packets.items():
        dest_ip_set = set(pkt['destination_ip'] for pkt in pkts)
        tcp_count = sum(1 for p in pkts if p['protocol'] == 'TCP')
        udp_count = sum(1 for p in pkts if p['protocol'] == 'UDP')
        syn_count = sum(1 for p in pkts if 'S' in p['tcp_flags'])
        fin_count = sum(1 for p in pkts if 'F' in p['tcp_flags'])
        push_count = sum(1 for p in pkts if 'P' in p['tcp_flags'])
        avg_size = sum(p['packet_size'] for p in pkts) / len(pkts)

        features.append({
            "source_ip": src_ip,
            "destination_ip": list(dest_ip_set),
            "packet_count": len(pkts),
            "avg_packet_size": avg_size,
            "syn_ratio": syn_count / len(pkts),
            "fin_ratio": fin_count / len(pkts),
            "push_ratio": push_count / len(pkts),
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "time_window_start": window_start
        })

    return features

# ----- Save Features for LS-DM -----
def save_features(features):
    with open("lsdm_input.json", "a") as f:
        for feat in features:
            f.write(json.dumps(feat) + "\n")

# ----- Main Loop -----
def main():
    print("Starting Custom Firewall + Feature Extractor...")
    while True:
        # sniff packets for a short duration
        sniff(prn=packet_logger, store=False, timeout=TIME_WINDOW)

        # extract features for LS-DM
        features = extract_features(packet_buffer)
        save_features(features)

        # print summary
        for feat in features:
            print(f"[LS-DM Input] {feat['source_ip']} -> Dest: {feat['destination_ip']} | Packets: {feat['packet_count']} | SYN ratio: {feat['syn_ratio']:.2f}")

        # clear buffer of old packets
        current_time = int(time.time())
        packet_buffer[:] = [p for p in packet_buffer if p['timestamp'] >= current_time - TIME_WINDOW]

if __name__ == "__main__":
    main()