"""
Intelligent Network Firewall - Packet Capture & Feature Extraction with ML
==================================================================
Captures live network packets using Scapy, extracts flow-based features
per source IP within a time window, applies trained ML model, and saves results as JSON.

Requirements:
    pip install scapy torch scikit-learn pandas joblib
    Run with root/admin privileges for live capture

Usage:
    sudo python main.py
    sudo python main.py -i eth0
    sudo python main.py -i eth0 -w 30
    sudo python main.py --file capture.pcap
    python main.py --demo
"""
import numpy as np # Add this to your imports at the top!
import json
import time
import argparse
import signal
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
# ─────────────────────────────────────────────
#  Optional imports
# ─────────────────────────────────────────────
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    print("[!] joblib not installed. Run: pip install joblib")
    JOBLIB_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    print("[!] torch not installed. Run: pip install torch")
    TORCH_AVAILABLE = False

# ─────────────────────────────────────────────
#  Scapy import (guarded)
# ─────────────────────────────────────────────
try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    print("[!] Scapy not available. Running in demo mode only.")
    SCAPY_AVAILABLE = False

# ─────────────────────────────────────────────
#  Paths  (DL model folder is one level above Firewall/)
# ─────────────────────────────────────────────
BASE_DIR           = Path(__file__).resolve().parent.parent
MODEL_DIR          = BASE_DIR / "DL model"

MODEL_PATH         = MODEL_DIR / "model.pkl"
SCALER_PATH        = MODEL_DIR / "scaler.pkl"
FEATURE_COLS_PATH  = MODEL_DIR / "feature_cols.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
DEFAULT_INTERFACE   = None
DEFAULT_TIME_WINDOW = 10
DEFAULT_OUTPUT_FILE = "features_new.json"
MAX_PACKETS         = 0  # 0 means run indefinitely

# ─────────────────────────────────────────────
#  TCP Flag Constants
# ─────────────────────────────────────────────
SYN_FLAG  = 0x02
FIN_FLAG  = 0x01
PUSH_FLAG = 0x08
ACK_FLAG  = 0x10
RST_FLAG  = 0x04

# ─────────────────────────────────────────────
#  Global State
# ─────────────────────────────────────────────
packet_store  = defaultdict(list)
all_features  = []
window_start  = time.time()
packet_total  = 0

# ─────────────────────────────────────────────
#  Model Architecture
# ─────────────────────────────────────────────
class FirewallNet(nn.Module):
    def __init__(self, input_size=12, num_classes=7, dropout=0.3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, 128),   # 0
            nn.BatchNorm1d(128),          # 1
            nn.ReLU(),                    # 2
            nn.Dropout(dropout),          # 3
            nn.Linear(128, 64),           # 4
            nn.BatchNorm1d(64),           # 5
            nn.ReLU(),                    # 6
            nn.Dropout(dropout),          # 7
            nn.Linear(64, 32),            # 8
            nn.BatchNorm1d(32),           # 9
            nn.ReLU(),                    # 10
            nn.Dropout(dropout),          # 11
            nn.Linear(32, num_classes),   # 12
        )

    def forward(self, x):
        return self.net(x)

# ─────────────────────────────────────────────
#  Load ML Model
# ─────────────────────────────────────────────
model           = None
scaler          = None
ml_feature_cols = None
le              = None
ML_AVAILABLE    = False
device          = torch.device("cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu") if TORCH_AVAILABLE else None

if TORCH_AVAILABLE and JOBLIB_AVAILABLE:
    try:
        # Load state dict and inject into architecture
        state_dict  = torch.load(str(MODEL_PATH), map_location=device)
        num_classes = state_dict["net.12.weight"].shape[0]  # 7
        input_size  = state_dict["net.0.weight"].shape[1]   # 12

        model = FirewallNet(input_size=input_size, num_classes=num_classes)
        model.load_state_dict(state_dict)
        model.to(device)
        model.eval()

        scaler          = joblib.load(str(SCALER_PATH))
        ml_feature_cols = joblib.load(str(FEATURE_COLS_PATH))
        le              = joblib.load(str(LABEL_ENCODER_PATH))

        ML_AVAILABLE = True
        print(f"[✓] ML model loaded  (input={input_size}, classes={num_classes}, device={device})")
        print(f"[✓] Classes: {list(le.classes_)}")

    except Exception as e:
        print(f"[!] Failed to load ML model: {e}")
        print("    → Running with heuristic labels only.")
        ML_AVAILABLE = False
else:
    print("[!] torch or joblib unavailable — ML model cannot be loaded.")

# Fallback feature columns
if not ML_AVAILABLE or ml_feature_cols is None:
    ml_feature_cols = [
        "packet_count", "avg_packet_size", "tcp_count", "udp_count",
        "syn_ratio", "fin_ratio", "push_ratio", "rst_ratio",
        "unique_dest_ports", "avg_inter_packet_time",
        "unique_dest_ips", "flow_bytes_per_sec",
    ]

# ─────────────────────────────────────────────
#  TCP Flag Helper
# ─────────────────────────────────────────────
def has_flag(flags, flag_mask):
    return bool(flags & flag_mask)

# ─────────────────────────────────────────────
#  Packet Parser
# ─────────────────────────────────────────────
def parse_packet(pkt):
    global packet_total

    if not pkt.haslayer(IP):
        return

    ip_layer  = pkt[IP]
    src_ip    = ip_layer.src
    dst_ip    = ip_layer.dst
    proto     = ip_layer.proto
    pkt_size  = len(pkt)
    timestamp = time.time()

    tcp_flags = 0
    src_port  = 0
    dst_port  = 0

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        src_port  = tcp_layer.sport
        dst_port  = tcp_layer.dport
        tcp_flags = int(tcp_layer.flags)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port  = udp_layer.sport
        dst_port  = udp_layer.dport

    packet_store[src_ip].append({
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  "TCP" if proto == 6 else ("UDP" if proto == 17 else "OTHER"),
        "pkt_size":  pkt_size,
        "tcp_flags": tcp_flags,
        "timestamp": timestamp
    })
    packet_total += 1

    if packet_total % 50 == 0:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Captured {packet_total} packets | "
              f"Active hosts: {len(packet_store)}")

# ─────────────────────────────────────────────
#  Feature Extraction
# ─────────────────────────────────────────────
def extract_features(src_ip, packets, window_start_ts):
    if not packets:
        return None

    n          = len(packets)
    timestamps = [p["timestamp"] for p in packets]
    sizes      = [p["pkt_size"]  for p in packets]
    dst_ips    = list({p["dst_ip"]  for p in packets})
    dst_ports  = {p["dst_port"] for p in packets}
    tcp_pkts   = [p for p in packets if p["protocol"] == "TCP"]
    udp_pkts   = [p for p in packets if p["protocol"] == "UDP"]

    syn_count  = sum(1 for p in tcp_pkts if has_flag(p["tcp_flags"], SYN_FLAG))
    fin_count  = sum(1 for p in tcp_pkts if has_flag(p["tcp_flags"], FIN_FLAG))
    push_count = sum(1 for p in tcp_pkts if has_flag(p["tcp_flags"], PUSH_FLAG))
    rst_count  = sum(1 for p in tcp_pkts if has_flag(p["tcp_flags"], RST_FLAG))

    sorted_ts = sorted(timestamps)
    if len(sorted_ts) > 1:
        inter_gaps = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
        avg_ipt    = round(sum(inter_gaps) / len(inter_gaps), 6)
    else:
        avg_ipt = 0.0

    ack_count  = sum(1 for p in tcp_pkts if has_flag(p["tcp_flags"], ACK_FLAG))

    flow_duration      = round(max(timestamps) - min(timestamps), 3)
    fwd_bytes          = sum(sizes)
    flow_bytes_per_sec = fwd_bytes / flow_duration if flow_duration > 0 else 0
    n = len(packets)
    sizes = [p["pkt_size"] for p in packets]
    pkt_len_std = round(np.std(sizes), 2) if n > 0 else 0
    feature = {
        "source_ip":             src_ip,
        "destination_ips":       dst_ips,
        "packet_count":          n,
        "avg_packet_size":       round(sum(sizes) / n, 2),
        "tcp_count":             len(tcp_pkts),
        "udp_count":             len(udp_pkts),
        "pkt_len_std":           pkt_len_std,
        "syn_ratio":             round(syn_count  / n, 4),
        "fin_ratio":             round(fin_count  / n, 4),
        "push_ratio":            round(push_count / n, 4),
        "rst_ratio":             round(rst_count  / n, 4),
        "ack_ratio":             round(ack_count  / n, 4),
        "unique_dest_ips":       len(dst_ips),
        "unique_dest_ports":     len(dst_ports),
        "avg_inter_packet_time": avg_ipt,
        "flow_duration":         flow_duration,
        "fwd_bytes":             fwd_bytes,
        "flow_bytes_per_sec":    round(flow_bytes_per_sec, 4),
        "time_window_start":     datetime.fromtimestamp(window_start_ts).isoformat(),
        "time_window_duration":  flow_duration,
    }

    # ── ML Prediction ──────────────────────────
    if ML_AVAILABLE :
        try:
            feature_vector = [feature[col] for col in ml_feature_cols]
            X_input = np.array([feature_vector], dtype=np.float32)
            X_scaled = scaler.transform(X_input)
            
            X_tensor = torch.tensor(X_scaled).to(device)
            with torch.no_grad():
                output = model(X_tensor)
                prob = torch.softmax(output, dim=1)
                conf, pred_idx = torch.max(prob, 1)
                
            if conf.item() > 0.85:
                ml_pred = le.inverse_transform([pred_idx.item()])[0]
            else:
                ml_pred = "Normal Traffic" 

            feature["ml_prediction"] = ml_pred

        except Exception as e:
            print(f"[!] Prediction error for {src_ip}: {e}")
            feature["ml_prediction"] = "ERROR"
    else:
        feature["ml_prediction"] = "N/A"

    return feature

# ─────────────────────────────────────────────
#  Heuristic Labeling
# ─────────────────────────────────────────────
def heuristic_label(feature):
    pc    = feature["packet_count"]
    syn   = feature["syn_ratio"]
    udp   = feature["udp_count"]
    ports = feature["unique_dest_ports"]
    ipt   = feature["avg_inter_packet_time"]

    if syn > 0.7 and pc > 50:    return "SYN_FLOOD"
    if udp > 100 and ipt < 0.01: return "UDP_FLOOD"
    if ports > 50:               return "PORT_SCAN"
    if pc > 200 and ipt < 0.005: return "DOS_FLOOD"
    return "NORMAL"

# ─────────────────────────────────────────────
#  Window Aggregator
# ─────────────────────────────────────────────
def aggregate_window(window_ts):
    global packet_store
    total_pkts = sum(len(v) for v in packet_store.values())
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Aggregating window "
          f"({len(packet_store)} IPs, {total_pkts} packets)")

    window_features = []
    for src_ip, packets in packet_store.items():
        feat = extract_features(src_ip, packets, window_ts)
        if feat:
            feat["label"] = heuristic_label(feat)
            window_features.append(feat)

            is_attack = feat["label"] != "NORMAL"
            ml_attack = ML_AVAILABLE and feat["ml_prediction"] not in ("NORMAL", "N/A", "ERROR")
            if is_attack or ml_attack:
                print(f"  ⚠  ALERT | {feat['label']:12s} | ML={feat['ml_prediction']} | "
                      f"src={src_ip} | packets={feat['packet_count']} | "
                      f"syn_ratio={feat['syn_ratio']}")

    # We don't necessarily need to keep everything in all_features if we save incrementally
    # but we'll keep it for the final save if needed, or just clear it to save RAM.
    # all_features.extend(window_features) 
    
    packet_store.clear()
    print(f"  → {len(window_features)} flow records extracted.\n")
    return window_features

# ─────────────────────────────────────────────
#  Save Features
# ─────────────────────────────────────────────
def save_features(output_file, features_to_append=None):
    """
    Saves features to JSON. If features_to_append is provided, 
    it will append them to the existing JSON list in the file efficiently.
    """
    import os
    
    if features_to_append:
        if not os.path.exists(output_file) or os.path.getsize(output_file) < 5:
            # Create new file with the list
            with open(output_file, "w") as f:
                json.dump(features_to_append, f, indent=2)
        else:
            # Append to existing JSON array efficiently
            try:
                with open(output_file, "rb+") as f:
                    f.seek(-1, os.SEEK_END)
                    # Find the last ']'
                    while f.tell() > 0:
                        f.seek(-1, os.SEEK_CUR)
                        char = f.read(1)
                        if char == b']':
                            f.seek(-1, os.SEEK_CUR)
                            break
                        f.seek(-1, os.SEEK_CUR)
                    
                    # Prepare new data
                    new_json = json.dumps(features_to_append, indent=2)
                    # Strip the leading '[' and trailing ']' from the new list
                    new_json = new_json.strip().lstrip('[').rstrip(']').strip()
                    
                    if new_json:
                        f.write(b",\n  ")
                        f.write(new_json.encode('utf-8'))
                        f.write(b"\n]")
            except Exception as e:
                print(f"[!] Error appending to {output_file}: {e}")
                # Fallback to read-all-write-all if something goes wrong
                existing_data = []
                try:
                    with open(output_file, "r") as f:
                        existing_data = json.load(f)
                except: pass
                existing_data.extend(features_to_append)
                with open(output_file, "w") as f:
                    json.dump(existing_data, f, indent=2)

        print(f"[✓] Features appended → {output_file} ({len(features_to_append)} new records)")
    else:
        # Final save of whatever is left in all_features (usually empty if we use incremental)
        if all_features:
            with open(output_file, "w") as f:
                json.dump(all_features, f, indent=2)
            print(f"[✓] Features saved → {output_file} ({len(all_features)} records)")

# ─────────────────────────────────────────────
#  Signal Handler (Ctrl+C)
# ─────────────────────────────────────────────
def signal_handler(sig, frame):
    print("\n[!] Capture interrupted by user.")
    if packet_store:
        aggregate_window(window_start)
    save_features(DEFAULT_OUTPUT_FILE)
    sys.exit(0)

# ─────────────────────────────────────────────
#  Demo Mode
# ─────────────────────────────────────────────
def run_demo_mode():
    import random
    global window_start
    window_start = time.time()

    NORMAL_IPS = ["192.168.1.10", "192.168.1.11"]
    ATTACK_IPS = {
        "10.0.0.99": "SYN_FLOOD",
        "10.0.0.88": "PORT_SCAN"
    }

    print("[*] Running in DEMO mode (no live capture)\n")

    for round_num in range(1, 4):
        print(f"[Demo] Round {round_num}/3")

        for ip in NORMAL_IPS:
            for _ in range(random.randint(10, 40)):
                packet_store[ip].append({
                    "src_ip":    ip,
                    "dst_ip":    f"93.184.{random.randint(1,50)}.{random.randint(1,200)}",
                    "src_port":  random.randint(49152, 65535),
                    "dst_port":  random.choice([80, 443]),
                    "protocol":  "TCP",
                    "pkt_size":  random.randint(64, 1500),
                    "tcp_flags": random.choice([ACK_FLAG, ACK_FLAG | PUSH_FLAG, FIN_FLAG | ACK_FLAG]),
                    "timestamp": time.time() + random.uniform(0, 9)
                })

        for ip, atype in ATTACK_IPS.items():
            if atype == "SYN_FLOOD":
                for _ in range(random.randint(150, 300)):
                    packet_store[ip].append({
                        "src_ip":    ip,
                        "dst_ip":    "192.168.1.1",
                        "src_port":  random.randint(1024, 65535),
                        "dst_port":  80,
                        "protocol":  "TCP",
                        "pkt_size":  60,
                        "tcp_flags": SYN_FLAG,
                        "timestamp": time.time() + random.uniform(0, 0.5)
                    })
            elif atype == "PORT_SCAN":
                for port in range(1, 80):
                    packet_store[ip].append({
                        "src_ip":    ip,
                        "dst_ip":    "192.168.1.1",
                        "src_port":  random.randint(1024, 65535),
                        "dst_port":  port,
                        "protocol":  "TCP",
                        "pkt_size":  60,
                        "tcp_flags": SYN_FLAG,
                        "timestamp": time.time() + random.uniform(0, 5)
                    })

        aggregate_window(window_start)
        window_start = time.time()
        time.sleep(0.5)

    save_features(DEFAULT_OUTPUT_FILE)

# ─────────────────────────────────────────────
#  Live Capture
# ─────────────────────────────────────────────
def run_live_capture(interface, time_window, output_file, max_packets):
    global window_start, packet_total
    signal.signal(signal.SIGINT, signal_handler)
    window_start = time.time()

    print(f"[*] Starting live capture on interface: {interface or 'default'}")
    print(f"    Time window : {time_window}s")
    print(f"    Max packets : {'Unlimited' if max_packets <= 0 else max_packets}")
    print(f"    Output file : {output_file}\n")

    def packet_handler(pkt):
        global window_start
        parse_packet(pkt)
        if time.time() - window_start >= time_window:
            new_feats = aggregate_window(window_start)
            save_features(output_file, features_to_append=new_feats)
            window_start = time.time()
        
        if max_packets > 0 and packet_total >= max_packets:
            raise SystemExit("Max packets reached.")

    sniff(iface=interface, prn=packet_handler, store=False, filter="ip")

    if packet_store:
        aggregate_window(window_start)
    save_features(output_file)

# ─────────────────────────────────────────────
#  Read from PCAP File
# ─────────────────────────────────────────────
def run_from_pcap(pcap_file, time_window, output_file):
    global window_start
    print(f"[*] Reading from PCAP: {pcap_file}")

    packets = rdpcap(pcap_file)
    if not packets:
        print("[!] No packets found in PCAP file.")
        return

    window_start = float(packets[0].time)
    for pkt in packets:
        parse_packet(pkt)
        if float(pkt.time) - window_start >= time_window:
            new_feats = aggregate_window(window_start)
            save_features(output_file, features_to_append=new_feats)
            window_start = float(pkt.time)

    if packet_store:
        aggregate_window(window_start)
    save_features(output_file)

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Intelligent Network Firewall with ML-based traffic classification"
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface for live capture (e.g. eth0)")
    parser.add_argument("-w", "--window",    type=int, default=DEFAULT_TIME_WINDOW,
                        help=f"Time window in seconds (default: {DEFAULT_TIME_WINDOW})")
    parser.add_argument("-o", "--output",    default=DEFAULT_OUTPUT_FILE,
                        help=f"Output JSON file (default: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--file",            default=None,
                        help="Read from a .pcap file instead of live capture")
    parser.add_argument("--demo",            action="store_true",
                        help="Run in demo mode with synthetic traffic (no root needed)")
    parser.add_argument("--max",             type=int, default=0,
                        help=f"Max packets to capture (default: 0 for unlimited)")
    args = parser.parse_args()

    if args.demo or not SCAPY_AVAILABLE:
        run_demo_mode()
    elif args.file:
        run_from_pcap(args.file, args.window, args.output)
    else:
        run_live_capture(args.interface, args.window, args.output, args.max)


if __name__ == "__main__":
    main()