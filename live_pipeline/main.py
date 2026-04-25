"""
Hybrid IDS — Heuristic + DL Fusion
=====================================
Combines:
  - Heuristic engine  (Code 1) → Port Scanning, DoS subtypes, Brute Force
  - DL model         (Code 3) → DoS vs Normal with confidence score
  - Fusion logic               → heuristic wins for scans, DL wins for floods

JSON log written to ids_logs.json — ready for dashboard visualisation.

Usage:
    python hybrid_ids.py
"""

from curses.ascii import SYN
import os
import sys
import time
import json
import torch
import joblib
import warnings
import numpy as np
import pandas as pd
import torch.nn as nn
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from nfstream import NFStreamer
from dotenv import load_dotenv


# it can load all env 
load_dotenv()


warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


# ═══════════════════════════════════════════════════════════════
#  1. PATHS
# ═══════════════════════════════════════════════════════════════
BASE_DIR           = Path(__file__).resolve().parent.parent
MODEL_DIR          = BASE_DIR / "models"
JSON_LOG_PATH      = BASE_DIR / "ids_logs.json"

MODEL_PATH         = MODEL_DIR / "model.pkl"
SCALER_PATH        = MODEL_DIR / "scaler.pkl"
FEATURE_COLS_PATH  = MODEL_DIR / "feature_cols.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"


# ═══════════════════════════════════════════════════════════════
#  2. CONFIGURATION
# ═══════════════════════════════════════════════════════════════
WIN_INTERFACE = os.getenv("WIN_INTERFACE")


#  but we can find out dos and port scanning . 
#! not ddos :)
ATTACK_CLASSES       = {"DoS", "DDoS", "Port Scanning", "Brute Force"} 
PORT_SCAN_THRESHOLD  = 20       # unique dst ports → Port Scan
FLOOD_FLOW_THRESHOLD = 50       # flows to ≤3 ports → flood
DL_CONFIDENCE_MIN    = 0.80     # below this → heuristic fallback


# ═══════════════════════════════════════════════════════════════
#  3. GLOBAL STATE (heuristic cross-flow trackers)
# ═══════════════════════════════════════════════════════════════
port_tracker = defaultdict(set)   # {src_ip: {dst_port, ...}}
flow_counter = defaultdict(int)   # {src_ip: flow_count}


# ═══════════════════════════════════════════════════════════════
#  4. DL MODEL
# ═══════════════════════════════════════════════════════════════
class SimpleMLP(nn.Module):
    def __init__(self, input_dim: int, num_classes: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(128, 64),        nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )


# ! find this forward and also find where is backward
    def forward(self, x):
        return self.network(x)


def load_dl_system():
    try:
        scaler       = joblib.load(SCALER_PATH) # load all data - math 
        le           = joblib.load(LABEL_ENCODER_PATH) # it give us labels 0 = Normal and 1 = DoS
        feature_cols = joblib.load(FEATURE_COLS_PATH) # list of features on which our model is trains 
        device       = torch.device("cuda" if torch.cuda.is_available() else "cpu") # i dont have cudo -> nvdia gpu 
        model        = SimpleMLP(len(feature_cols), len(le.classes_)).to(device) # empty version of the SimpleMLP
        

#A "State Dict" is just a big dictionary (list) of all the Weights and Biases the AI learned during training.
#This line takes those learned numbers and "plugs" them into the neurons of your SimpleMLP model.
        model.load_state_dict( 
            torch.load(MODEL_PATH,
                        map_location=device, # use my device 
                          weights_only=True #secuirty check that in file there will be just weights not any malicious script 

                          )
        )
        model.eval() # after traning it give us best model 

        print(f"  DL model loaded  : {len(feature_cols)} features, "
              f"classes={list(le.classes_)}, device={device}")
        return model, scaler, le, feature_cols, device
    except Exception as e:
        print(f"[!] DL model loading failed: {e}")
        sys.exit(1)

MODEL, SCALER, LE, FEATURE_COLS, DEVICE = load_dl_system()


#* start from here 
# ═══════════════════════════════════════════════════════════════
#  5. FEATURE EXTRACTION  (identical in both original scripts)
# ═══════════════════════════════════════════════════════════════
def extract_features(flow) -> dict:
    def safe_div(a, b): return float(a) / float(b) if b and b != 0 else 0.0

    # Convert milliseconds → microseconds
    def to_us(ms):      return float(ms) * 1000.0  if ms           else 0.0

    duration_s    = max(flow.bidirectional_duration_ms, 1.0) / 1000.0
    HDR           = 20
    # payload is total bytes minus the header size (assuming fixed header length per packet)
    fwd_payload   = max(0, flow.src2dst_bytes - flow.src2dst_packets * HDR)
    bwd_payload   = max(0, flow.dst2src_bytes - flow.dst2src_packets * HDR)
    total_payload = fwd_payload + bwd_payload

    return {
        "FIN Flag Count":              flow.bidirectional_fin_packets,
        "ACK Flag Count":              flow.bidirectional_ack_packets,
        "PSH Flag Count":              flow.bidirectional_psh_packets,
        "Init_Win_bytes_forward":      0,
        "Init_Win_bytes_backward":     0,
        "min_seg_size_forward":        0,
        "act_data_pkt_fwd":            0,
        "Total Fwd Packets":           flow.src2dst_packets,
        "Total Length of Fwd Packets": fwd_payload,
        "Destination Port":            flow.dst_port,
        "Flow Packets/s":              safe_div(flow.bidirectional_packets, duration_s),
        "Flow Bytes/s":                safe_div(total_payload, duration_s),
        "Fwd Packets/s":               safe_div(flow.src2dst_packets, duration_s),
        "Bwd Packets/s":               safe_div(flow.dst2src_packets, duration_s),
        # Inter-Arrival Time (IAT)
        "Flow IAT Mean":               to_us(flow.bidirectional_mean_piat_ms),
        "Flow IAT Min":                to_us(flow.bidirectional_min_piat_ms),
        "Flow IAT Std":                to_us(flow.bidirectional_stddev_piat_ms),
        "Flow Duration":               to_us(flow.bidirectional_duration_ms),
        "Fwd Packet Length Max":       flow.src2dst_max_ps,
        "Fwd Packet Length Min":       flow.src2dst_min_ps,
        "Fwd Packet Length Mean":      flow.src2dst_mean_ps,
        "Fwd Packet Length Std":       flow.src2dst_stddev_ps,
        "Bwd Packet Length Max":       flow.dst2src_max_ps,
        "Bwd Packet Length Min":       flow.dst2src_min_ps,
        "Bwd Packet Length Mean":      flow.dst2src_mean_ps,
        "Bwd Packet Length Std":       flow.dst2src_stddev_ps,
        "Flow IAT Max":                to_us(flow.bidirectional_max_piat_ms),
        "Fwd IAT Total":               to_us(flow.src2dst_duration_ms),
        "Fwd IAT Mean":                to_us(flow.src2dst_mean_piat_ms),
        "Fwd IAT Std":                 to_us(flow.src2dst_stddev_piat_ms),
        "Fwd IAT Max":                 to_us(flow.src2dst_max_piat_ms),
        "Fwd IAT Min":                 to_us(flow.src2dst_min_piat_ms),
        "Bwd IAT Total":               to_us(flow.dst2src_duration_ms),
        "Bwd IAT Mean":                to_us(flow.dst2src_mean_piat_ms),
        "Bwd IAT Std":                 to_us(flow.dst2src_stddev_piat_ms),
        "Bwd IAT Max":                 to_us(flow.dst2src_max_piat_ms),
        "Bwd IAT Min":                 to_us(flow.dst2src_min_piat_ms),
        "Fwd Header Length":           flow.src2dst_packets * HDR,
        "Bwd Header Length":           flow.dst2src_packets * HDR,
        "Min Packet Length":           flow.bidirectional_min_ps,
        "Max Packet Length":           flow.bidirectional_max_ps,
        "Packet Length Mean":          flow.bidirectional_mean_ps,
        "Packet Length Std":           flow.bidirectional_stddev_ps,
        "Packet Length Variance":      flow.bidirectional_stddev_ps ** 2,
        "Average Packet Size":         safe_div(total_payload, flow.bidirectional_packets),
        "Subflow Fwd Bytes":           fwd_payload,
        "Active Mean": 0.0, "Active Max": 0.0, "Active Min": 0.0,
        "Idle Mean":   0.0, "Idle Max":   0.0, "Idle Min":   0.0,
    }


# ═══════════════════════════════════════════════════════════════
#  6. HEURISTIC ENGINE  (from Code 1 / data collector)
#     Returns label string — authoritative for Port Scanning
# ═══════════════════════════════════════════════════════════════


#  it alwasy handle one flow at a time but it can keep track of the history of flows from each src ip to detect patterns like port scanning or flooding.


def heuristic_label(flow, features: dict) -> str:
    pkts      = max(flow.bidirectional_packets, 1)
    syn       = flow.bidirectional_syn_packets
    fin       = flow.bidirectional_fin_packets
    rst       = flow.bidirectional_rst_packets
    ack       = flow.bidirectional_ack_packets
    psh       = flow.bidirectional_psh_packets
    fwd_pkts  = flow.src2dst_packets 
    bwd_pkts  = flow.dst2src_packets
    pkt_rate  = features["Flow Packets/s"]
    byte_rate = features["Flow Bytes/s"]
    avg_size  = features["Average Packet Size"]
    dst_port  = flow.dst_port
    protocol  = flow.protocol
    dst_ip    = flow.dst_ip
    syn_ratio = syn / pkts
    psh_ratio = psh / pkts

    # ── update cross-flow trackers ────────────────────────
    port_tracker[flow.src_ip].add(dst_port) # we get the ports on whcih src ip is sending the packets  , port tracker store all the ports data with ip 
    # port_tracker["192.168.1.5"] = {22, 80, 443, 3306, 3389, 8080, 21}


    flow_counter[flow.src_ip] += 1  # we count how many flows are coming from this src ip
    print("flow_counter", flow_counter )

    unique_ports = len(port_tracker[flow.src_ip])
    is_scan      = unique_ports >= PORT_SCAN_THRESHOLD

    # If one IP creates 50 or more flows, but only to a very small number of ports (≤ 3) → it is considered a FLOOD attack.
    is_flood     = (flow_counter[flow.src_ip] >= FLOOD_FLOW_THRESHOLD
                    and unique_ports <= 3) 
    # print("is_flood", is_flood )

    is_broadcast = (dst_ip.endswith(".255") or dst_ip.startswith("224.")
                    or dst_ip.startswith("239.") or dst_ip.startswith("192."))
    #  i addres 192 bcz it was detecting the router as an attack 

    # ── UDP port scan (nmap -sU) ──────────────────────────
    #  if we get 2 or less packets to 1 port and no reply, but we see many unique ports over time, it's likely a UDP scan
    #  fwd_pkt pakcs comming from src to dst and bwd_pkt is packets comming from dst to src
    if protocol == 17 and fwd_pkts <= 2 and bwd_pkts == 0 and is_scan:
        return "Port Scanning"

    # ── SYN with no reply ────────────────────────────────
    # it might be two possiblities  : 
    # 1 - port scanning (if many unique ports seen from this src_ip over time) but no replies
    # 2 - DoS (if many flows to few ports, even without many unique ports, it's likely a flood)

    if fwd_pkts == 1 and bwd_pkts == 0 and syn >= 1:
        if is_scan:  return "Port Scanning"
        if is_flood: return "DoS"
        return "Normal Traffic"

    # ── catch-all TCP port scan ───────────────────────────
    # Flow 1:  SYN → port 21   (fwd=1, bwd=0)
    # Flow 2:  SYN → port 22   (fwd=1, bwd=0)
    # Flow 3:  SYN → port 23   (fwd=1, bwd=0)
    # Flow 4:  SYN → port 25   (fwd=1, bwd=0)
    # ...
    # Flow 50: SYN → port 443  (fwd=1, bwd=0)


    if is_scan and fwd_pkts <= 2 and bwd_pkts == 0:
        return "Port Scanning"

    # ── SYN flood (high ratio, many packets) ─────────────
    if syn_ratio > 0.7 and pkts > 50 and fin == 0:
        return "DoS"
    


    
# ! we have to start from here
    # ── SYN + RST (closed port probe) ────────────────────
  # nmap -sS  | here we stealth scan.
  
#   Normal connection:
#     SYN ──► SYN+ACK ──► ACK  (handshake completes, connection logged)

#     SYN scan:
#     SYN ──► SYN+ACK ──► RST  (handshake NEVER completes, nothing logged)
    if fwd_pkts <= 2 and syn >= 1 and rst >= 1 and psh == 0 and fin == 0:
        if is_scan: return "Port Scanning"
        return "Normal Traffic"

    # ── FIN/NULL/XMAS scan ───────────────────────────────
    #  just fin or just psh+fin or just urg+psh+fin with no reply, but many unique ports over time → likely a stealthy scan
    if fwd_pkts <= 2 and bwd_pkts == 0 and syn == 0 and fin >= 1 and ack == 0:
        if is_scan: return "Port Scanning"
        return "Normal Traffic"

    # ── RST+ACK teardown (normal) ────────────────────────
    # rst flag : Stop everything. This connection is dead. Do not send more data. Do not wait. Just drop it now
    if rst >= 1 and ack >= 1 and syn == 0 and fin == 0:
        return "Normal Traffic"

    # ── ACK scan (nmap -sA) ──────────────────────────────
    #  this attack just send ack signal to the target - if there will be firewall then it will drop the packet and if there is no firewall then it will reply with rst signal

    if fwd_pkts <= 2 and bwd_pkts == 0 and ack >= 1 and syn == 0 and fin == 0:
        if is_scan: return "Port Scanning"
        return "Normal Traffic"

    # ── SYN flood (lower threshold) ──────────────────────
    if syn_ratio > 0.7 and pkts > 20 and fin == 0:
        return "DoS"

    # ── HTTP flood ────────────────────────────────────────
    # 1st condtion :
    # first check http and http alternative ports 


    # 2nd condition : 
    #     pkt_rate > 500
    #  More than 500 packets per second
    #  Normal browsing = maybe 10-50 pkt/s
    # 500+ means someone is hammering the server


    # 3rd condition : 
# bwd_pkts < fwd_pkts * 0.1
# backward packets = responses FROM server
# forward packets = requests TO server
#
# Normal browsing:
# fwd: 10 requests → bwd: 10 responses (balanced)
#
# HTTP flood:
# fwd: 1000 requests → bwd: 5 responses (server is drowning)
# server cant keep up, response rate collapses

#  bwd > fwd * 0.1  =  we check that bwd packts are 10% of fwd packets or less



    if dst_port in (80, 443, 8080, 8443):
        if pkt_rate > 500 and psh_ratio > 0.3 and bwd_pkts < fwd_pkts * 0.1:
            return "DoS"
#         byte_rate > 500_000
# # more than 500 KB per second being sent
# # could be POST flood — sending huge request bodies
# # e.g. attacker sends massive form data / file uploads repeatedly
# pythonbwd_pkts < 5
# # server sent back almost NOTHING
# # means server is completely overwhelmed
# # cant even send a single HTTP response back
        if byte_rate > 500_000 and bwd_pkts < 5:
            return "DoS"



    # ── UDP DDoS ─────────────────────────────────────────
    if protocol == 17 and not is_broadcast:
        dur = flow.bidirectional_duration_ms
            # 500+ packets per second — extremely high for UDP 
            # pkt rate high
        if pkt_rate > 500 and flow.bidirectional_packets > 50 and dur < 1000:
            return "DDoS"
        # big size + high rate + many packets in a short time → classic UDP flood
        if byte_rate > 500_000 and flow.bidirectional_packets > 50 and dur < 1000:
            return "DDoS"

    # ── UDP flood (few ports, many flows) ────────────────
    if protocol == 17 and fwd_pkts <= 2 and not is_broadcast:
        if is_scan:  return "Port Scanning"
        if is_flood: return "DoS"
        return "Normal Traffic"

    # ── general high-rate ─────────────────────────────────
    if flow.bidirectional_packets >= 50:
        if pkt_rate > 3000:                        return "DDoS"
        if pkt_rate > 1000 and avg_size < 100:     return "DoS"

    # ── brute force ───────────────────────────────────────
    # if dst_port in (22, 21, 3389, 23, 25, 110, 143) and pkts > 10 and avg_size < 200:
    #     return "Brute Force"

    # return "Normal Traffic"


# ═══════════════════════════════════════════════════════════════
#  7. DL CLASSIFY  (from Code 3)
# ═══════════════════════════════════════════════════════════════
def dl_classify(features: dict):
    arr = np.array(
        [[features.get(col, 0) for col in FEATURE_COLS]], dtype=np.float32
    )
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
    arr = SCALER.transform(arr)
    t   = torch.tensor(arr, dtype=torch.float32).to(DEVICE)

    with torch.no_grad():
        logits = MODEL(t)
        if torch.isnan(logits).any():
            return "Normal Traffic", 0.0
        probs      = torch.softmax(logits, dim=1)
        conf, idx  = torch.max(probs, 1)

    label = LE.inverse_transform([idx.item()])[0]
    return label, round(conf.item(), 4)


# ═══════════════════════════════════════════════════════════════
#  8. HYBRID FUSION  ← the new brain
#
#  Priority order:
#    1. Heuristic → Port Scanning  (DL cannot detect this)
#    2. Heuristic → Brute Force    (DL not trained on this)
#    3. Heuristic → DDoS           (DL not trained on this)
#    4. High-confidence DL         (≥ DL_CONFIDENCE_MIN)
#    5. Both agree                 (any confidence)
#    6. Heuristic fallback         (DL uncertain / disagrees)
# ═══════════════════════════════════════════════════════════════
def hybrid_classify(flow, features: dict):
    h_label              = heuristic_label(flow, features)
    dl_label, dl_conf    = dl_classify(features)

    # Rule 1 — heuristic is the only thing that can catch scans
    if h_label == "Port Scanning":
        return "Port Scanning", 1.0, "heuristic"

    # Rule 2 — attack types DL was never trained on
    if h_label in ("Brute Force", "DDoS"):
        return h_label, 1.0, "heuristic"

    # Rule 3 — high-confidence DL prediction
    if dl_conf >= DL_CONFIDENCE_MIN:
        return dl_label, dl_conf, "dl"

    # Rule 4 — both layers agree (even at lower confidence)
    if h_label == dl_label:
        return dl_label, dl_conf, "both"

    # Rule 5 — heuristic says attack, DL is uncertain → trust heuristic
    if h_label != "Normal Traffic":
        return h_label, dl_conf, "heuristic_fallback"

    # Rule 6 — default to DL result
    return dl_label, dl_conf, "dl_fallback"


# ═══════════════════════════════════════════════════════════════
#  9. JSON LOGGER  (rich format for dashboard)
# ═══════════════════════════════════════════════════════════════
def log_to_json(flow, features, final_label, dl_label, dl_conf,
                h_label, decided_by, pkt_count):
    entry = {
        # ── identity ──────────────────────────────────────
        "timestamp":     datetime.now().isoformat(),
        "source_ip":     flow.src_ip,
        "dest_ip":       flow.dst_ip,
        "dest_port":     flow.dst_port,
        "protocol":      "TCP" if flow.protocol == 6 else "UDP",

        # ── final verdict ─────────────────────────────────
        "final_label":   final_label,
        "is_attack":     final_label in ATTACK_CLASSES,
        "decided_by":    decided_by,   # "heuristic" | "dl" | "both" | fallback

        # ── DL layer detail ───────────────────────────────
        "dl_prediction": dl_label,
        "dl_confidence": dl_conf,

        # ── heuristic layer detail ────────────────────────
        "heuristic_label":   h_label,
        "unique_ports_seen": len(port_tracker[flow.src_ip]),
        "flows_from_ip":     flow_counter[flow.src_ip],

        # ── traffic stats ─────────────────────────────────
        "packet_count":  pkt_count,
        "pkt_per_sec":   round(features["Flow Packets/s"], 2),
        "bytes_per_sec": round(features["Flow Bytes/s"], 2),
        "duration_ms":   flow.bidirectional_duration_ms,

        # ── flag breakdown ────────────────────────────────
        "flags": {
            "SYN": flow.bidirectional_syn_packets,
            "FIN": flow.bidirectional_fin_packets,
            "RST": flow.bidirectional_rst_packets,
            "ACK": flow.bidirectional_ack_packets,
            "PSH": flow.bidirectional_psh_packets,
        }
    }

    data = []
    if JSON_LOG_PATH.exists():
        try:
            with open(JSON_LOG_PATH, "r") as f:
                data = json.load(f)
        except Exception:
            data = []

    data.append(entry)

    # keep only last 5000 entries so file doesn't grow forever
    if len(data) > 5000:
        data = data[-5000:]

    with open(JSON_LOG_PATH, "w") as f:
        json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════
#  10. TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════
COLORS = {
    "Normal Traffic": "\033[92m",   # green
    "Port Scanning":  "\033[93m",   # yellow
    "DoS":            "\033[91m",   # red
    "DDoS":           "\033[91m",   # red
    "Brute Force":    "\033[95m",   # magenta
}
RESET  = "\033[0m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

SOURCE_BADGE = {
    "heuristic":          "[H]   ",
    "dl":                 "  [D] ",
    "both":               "[H+M] ",
    "heuristic_fallback": "[H~]  ",
    "dl_fallback":        "  [D~]",
}


def print_flow(flow, features, final_label, dl_label, dl_conf,
               h_label, decided_by, flow_num):
    color  = COLORS.get(final_label, "\033[97m")
    badge  = SOURCE_BADGE.get(decided_by, "      ")
    ts     = time.strftime("%H:%M:%S")
    proto  = "TCP" if flow.protocol == 6 else "UDP"
    ports  = len(port_tracker[flow.src_ip])

    print(
        f"[{ts}] #{flow_num:<5} {badge} "
        f"{flow.src_ip:<16} → {flow.dst_ip:<16} "
        f"port={flow.dst_port:<6} {proto:<4} "
        f"pkts={flow.bidirectional_packets:<5} "
        f"{color}{final_label:<16}{RESET}"
        f"{GRAY}  dl={dl_label}({dl_conf:.0%})  "
        f"h={h_label}  ports_seen={ports}{RESET}"
    )

    if final_label in ATTACK_CLASSES:
        pkts = max(flow.bidirectional_packets, 1)
        print(
            f"           "
            f"SYN={flow.bidirectional_syn_packets}({flow.bidirectional_syn_packets/pkts:.0%}) "
            f"FIN={flow.bidirectional_fin_packets} "
            f"RST={flow.bidirectional_rst_packets}({flow.bidirectional_rst_packets/pkts:.0%}) "
            f"PSH={flow.bidirectional_psh_packets}({flow.bidirectional_psh_packets/pkts:.0%}) "
            f"→ {features['Flow Packets/s']:.0f}pkt/s  "
            f"{features['Flow Bytes/s']:.0f}B/s"
        )


# ═══════════════════════════════════════════════════════════════
#  11. MAIN LOOP
# ═══════════════════════════════════════════════════════════════
def run(interface: str):
    print("=" * 80)
    print("  Hybrid IDS  —  Heuristic + DL Fusion")
    print("=" * 80)
    print(f"  Interface      : {interface}")
    print(f"  JSON log       : {JSON_LOG_PATH}")
    print(f"  DL conf thresh : {DL_CONFIDENCE_MIN:.0%}")
    print(f"  Scan threshold : {PORT_SCAN_THRESHOLD} unique ports")
    print(f"  Flood threshold: {FLOOD_FLOW_THRESHOLD} flows to ≤3 ports")
    print()
    print("  Decision badge key:")
    print("    [H]    heuristic authoritative  (port scan / DDoS / brute force)")
    print("    [D]    DL authoritative         (high confidence DoS / Normal)")
    print("    [H+M]  both layers agree")
    print("    [H~]   heuristic fallback       (DL uncertain, heuristic says attack)")
    print("    [D~]   DL fallback              (heuristic says normal, DL decides)")
    print()
    print("  Press Ctrl+C to stop\n")
    print("─" * 80)

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,
        idle_timeout=10,
        active_timeout=30,
        accounting_mode=1,
    )

    flow_num     = 0
    label_counts = defaultdict(int)
    source_counts = defaultdict(int)

    try:
        for flow in streamer:
            flow_num += 1
            features = extract_features(flow)

            final_label, final_conf, decided_by = hybrid_classify(flow, features)

            # recover h_label and dl_label for logging
            # (hybrid_classify already updated port_tracker inside heuristic_label,
            #  so we read the result without updating counters again)
            h_label              = heuristic_label.__wrapped__(flow, features) \
                                   if hasattr(heuristic_label, "__wrapped__") \
                                   else _peek_heuristic(flow, features)
            dl_label, dl_conf    = dl_classify(features)

            label_counts[final_label] += 1
            source_counts[decided_by] += 1

            log_to_json(
                flow, features,
                final_label, dl_label, dl_conf,
                h_label, decided_by,
                flow.bidirectional_packets
            )

            print_flow(
                flow, features,
                final_label, dl_label, dl_conf,
                h_label, decided_by, flow_num
            )

            # summary every 50 flows
            if flow_num % 50 == 0:
                total = sum(label_counts.values())
                print(f"\n  ── {flow_num} flows processed ──")
                for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
                    bar = "█" * min(int(cnt / total * 30), 30)
                    col = COLORS.get(lbl, "")
                    print(f"    {col}{lbl:<18}{RESET} {cnt:>5} ({cnt/total:.0%})  {bar}")
                print(f"  Decision sources: {dict(source_counts)}\n")

    except KeyboardInterrupt:
        print("\n[!] IDS shutting down.")

    finally:
        total = sum(label_counts.values())
        if total:
            print(f"\n{'='*80}")
            print(f"  Session summary — {total} flows")
            print(f"{'='*80}")
            for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
                pct = cnt / total * 100
                bar = "█" * min(int(pct), 40)
                col = COLORS.get(lbl, "")
                print(f"    {col}{lbl:<18}{RESET} {cnt:>6} ({pct:5.1f}%)  {bar}")
            print(f"\n  Decision source breakdown: {dict(source_counts)}")
            print(f"  JSON log saved → {JSON_LOG_PATH}")
            print(f"{'='*80}\n")


# ── helper: read heuristic label without double-updating counters ──
def _peek_heuristic(flow, features: dict) -> str:
    """
    Returns what the heuristic *would* say for this flow using the
    current (already-updated) port_tracker state, without modifying
    any counters a second time.
    """
    pkts      = max(flow.bidirectional_packets, 1)
    syn       = flow.bidirectional_syn_packets
    fin       = flow.bidirectional_fin_packets
    rst       = flow.bidirectional_rst_packets
    ack       = flow.bidirectional_ack_packets
    psh       = flow.bidirectional_psh_packets
    fwd_pkts  = flow.src2dst_packets
    bwd_pkts  = flow.dst2src_packets
    pkt_rate  = features["Flow Packets/s"]
    byte_rate = features["Flow Bytes/s"]
    avg_size  = features["Average Packet Size"]
    dst_port  = flow.dst_port
    protocol  = flow.protocol
    dst_ip    = flow.dst_ip

    syn_ratio = syn / pkts
    psh_ratio = psh / pkts

    # read-only — port_tracker already updated inside hybrid_classify
    unique_ports = len(port_tracker[flow.src_ip])
    flows_ip     = flow_counter[flow.src_ip]
    is_scan      = unique_ports >= PORT_SCAN_THRESHOLD
    is_flood     = flows_ip >= FLOOD_FLOW_THRESHOLD and unique_ports <= 3
    is_broadcast = (dst_ip.endswith(".255") or dst_ip.startswith("224.")
                    or dst_ip.startswith("239.") or dst_ip.startswith("1."))

    if protocol == 17 and fwd_pkts <= 2 and bwd_pkts == 0 and is_scan:
        return "Port Scanning"
    if fwd_pkts == 1 and bwd_pkts == 0 and syn >= 1:
        if is_scan:  return "Port Scanning"
        if is_flood: return "DoS"
        return "Normal Traffic"
    if is_scan and fwd_pkts <= 2 and bwd_pkts == 0:
        return "Port Scanning"
    if syn_ratio > 0.7 and pkts > 50 and fin == 0:
        return "DoS"
    if fwd_pkts <= 2 and syn >= 1 and rst >= 1 and psh == 0 and fin == 0:
        return "Port Scanning" if is_scan else "Normal Traffic"
    if fwd_pkts <= 2 and bwd_pkts == 0 and syn == 0 and fin >= 1 and ack == 0:
        return "Port Scanning" if is_scan else "Normal Traffic"
    if rst >= 1 and ack >= 1 and syn == 0 and fin == 0:
        return "Normal Traffic"
    if fwd_pkts <= 2 and bwd_pkts == 0 and ack >= 1 and syn == 0 and fin == 0:
        return "Port Scanning" if is_scan else "Normal Traffic"
    if syn_ratio > 0.7 and pkts > 20 and fin == 0:
        return "DoS"
    if dst_port in (80, 443, 8080, 8443):
        if pkt_rate > 500 and psh_ratio > 0.3 and bwd_pkts < fwd_pkts * 0.1:
            return "DoS"
        if byte_rate > 500_000 and bwd_pkts < 5:
            return "DoS"
    if protocol == 17 and not is_broadcast:
        dur = flow.bidirectional_duration_ms
        if pkt_rate > 500 and flow.bidirectional_packets > 50 and dur < 1000:
            return "DDoS"
        if byte_rate > 500_000 and flow.bidirectional_packets > 50 and dur < 1000:
            return "DDoS"
    if protocol == 17 and fwd_pkts <= 2 and not is_broadcast:
        if is_scan:  return "Port Scanning"
        if is_flood: return "DoS"
        return "Normal Traffic"
    if flow.bidirectional_packets >= 50:
        if pkt_rate > 3000:                    return "DDoS"
        if pkt_rate > 1000 and avg_size < 100: return "DoS"
    if dst_port in (22, 21, 3389, 23, 25, 110, 143) and pkts > 10 and avg_size < 200:
        return "Brute Force"
    return "Normal Traffic"


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # WIN_INTERFACE = r"\Device\NPF_{F5DC9C1F-1E2A-4E87-B26B-35ACD6616711}"
    
    run(WIN_INTERFACE)
