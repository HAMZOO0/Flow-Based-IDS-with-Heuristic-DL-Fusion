

import os
import time
import pandas as pd
from pathlib import Path
from collections import defaultdict
from nfstream import NFStreamer
from dotenv import load_dotenv


# it can load all env 
load_dotenv()
# ─────────────────────────────────────────────
#  DYNAMIC PATHING
# ─────────────────────────────────────────────
BASE_DIR      = Path(__file__).resolve().parent.parent
CSV_PATH      = BASE_DIR / "captured_flows.csv"
WIN_INTERFACE = os.getenv("WIN_INTERFACE")

# ─────────────────────────────────────────────
#  PORT TRACKER
#  Tracks unique destination ports per source IP
#  across all flows — used to distinguish
#  port scanning (many ports) from DoS (one port)
# ─────────────────────────────────────────────
port_tracker = defaultdict(set)   # {src_ip: {port1, port2, ...}}
flow_counter = defaultdict(int)     # {src_ip: flow_count}  ← ADD THIS
PORT_SCAN_THRESHOLD = 20           # unique ports before calling it a scan
FLOOD_FLOW_THRESHOLD = 50           # flows to same port = flood ← ADD THIS


# ─────────────────────────────────────────────
#  HEURISTIC LABELER
# ─────────────────────────────────────────────
def heuristic_label(flow, features: dict) -> str:

    pkts       = max(flow.bidirectional_packets, 1)
    syn        = flow.bidirectional_syn_packets
    fin        = flow.bidirectional_fin_packets
    rst        = flow.bidirectional_rst_packets
    ack        = flow.bidirectional_ack_packets
    psh        = flow.bidirectional_psh_packets
    fwd_pkts   = flow.src2dst_packets
    bwd_pkts   = flow.dst2src_packets
    pkt_rate   = features["Flow Packets/s"]
    byte_rate  = features["Flow Bytes/s"]
    avg_size   = features["Average Packet Size"]
    dst_port   = flow.dst_port
    protocol   = flow.protocol

    syn_ratio  = syn / pkts
    rst_ratio  = rst / pkts
    fin_ratio  = fin / pkts
    psh_ratio  = psh / pkts

    # Track unique ports this src IP has touched
    port_tracker[flow.src_ip].add(dst_port)
    flow_counter[flow.src_ip] += 1          # flow per ip 
    unique_ports = len(port_tracker[flow.src_ip])
    is_scan      = unique_ports >= PORT_SCAN_THRESHOLD
    is_flood     = (flow_counter[flow.src_ip] >= FLOOD_FLOW_THRESHOLD
                    and unique_ports <= 3)   # many flows, few ports = flood

    # ── PORT SCANNING vs DoS ─────────────────────────────
    #
    # IMPORTANT: Single-packet flows are very common in normal
    # traffic (DNS, UDP, incomplete TCP handshakes).
    # Only flag as scan/DoS if we have STRONG evidence.
    #
    # Strong evidence = attacker IP has hit many ports (is_scan)
    # OR packet rate is very high (flood)

    # SYN sent, no reply — only flag if clearly a scan or flood

 # ── UDP PORT SCAN (nmap -sU) ──────────────────────────
    # UDP scans send 1 packet to each port with no flags
    # Normal UDP traffic goes to same port repeatedly
    # nmap -sU hits hundreds of different ports
    if protocol == 17 and fwd_pkts <= 2 and bwd_pkts == 0 and is_scan: # if we remove bwd_pkts  its ok bcz udp don't have any ack flag 
        return "Port Scanning"

        

   # SYN with no reply
    if fwd_pkts == 1 and bwd_pkts == 0 and syn >= 1:
        if is_scan:
            return "Port Scanning"   # many ports = nmap
        if is_flood:
            return "DoS"             # many flows, same port = hping3 flood
        return "Normal Traffic"      # not enough evidence yet

          # ── CATCH-ALL PORT SCAN ──────────────────────────────
    # If an IP has hit 20+ unique ports with tiny flows
    # it's definitely scanning regardless of flags
    if is_scan and fwd_pkts <= 2 and bwd_pkts == 0:
        return "Port Scanning"

    # ── SYN FLOOD DETECTION ──────────────────────────────
    # hping3 --flood -S creates MANY flows to same port
    # Each flow = 1 SYN packet, same port, no reply
    # Normal browser = 1-3 SYN to same port max
    # flow_count_this_ip = sum(1 for p in port_tracker[flow.src_ip]
    #                          if True)  # port_tracker has ports not flows

    # Better: track flow counts separately
    if syn_ratio > 0.7 and pkts > 50 and fin == 0:
        return "DoS"

    # SYN sent, RST received (port closed) — strong scan signal
    if fwd_pkts <= 2 and syn >= 1 and rst >= 1 and psh == 0 and fin == 0:
        if is_scan:
            return "Port Scanning"
        return "Normal Traffic"      # single closed port = normal

    # FIN/NULL/XMAS scan — only nmap does this deliberately
    if fwd_pkts <= 2 and bwd_pkts == 0 and syn == 0 and fin >= 1 and ack == 0:
        if is_scan:
            return "Port Scanning"
        return "Normal Traffic"

    # ACK scan (nmap -sA) — only flag if many ports scanned
    # BUT exclude RST+ACK — this is normal TCP connection teardown
    # Real ACK scans send pure ACK with no RST
    is_rst_ack_teardown = (rst >= 1 and ack >= 1 and syn == 0 and fin == 0)
    if is_rst_ack_teardown:
        return "Normal Traffic"

    if fwd_pkts <= 2 and bwd_pkts == 0 and ack >= 1 and syn == 0 and fin == 0:
        if is_scan:
            return "Port Scanning"
        return "Normal Traffic"

    # ── SYN FLOOD ────────────────────────────────────────
    if syn_ratio > 0.7 and pkts > 20 and fin == 0:
        return "DoS"

    # ── HTTP FLOOD (ab / curl flood) ─────────────────────
    # Normal HTTPS traffic easily hits 70KB/s and 100 pkts/s
    # Real floods are much more aggressive AND one-sided
    if dst_port in (80, 443, 8080, 8443):
        # Must be high rate AND one-sided (attacker sends, no real response)
        if pkt_rate > 500 and psh_ratio > 0.3 and bwd_pkts < fwd_pkts * 0.1:
            return "DoS"
        # Very high byte rate with almost no server response = flood
        if byte_rate > 500000 and bwd_pkts < 5:
            return "DoS"
        
# ── UDP FLOOD ─────────────────────────────────────────
    # Ignore broadcast/multicast — these are normal LAN traffic
    # 192.168.x.255 = broadcast, 224.x.x.x = multicast
    dst_ip = flow.dst_ip
    is_broadcast = dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239.")or dst_ip.startswith("1.")

    if protocol == 17 and not is_broadcast:
        # Real UDP floods are fast AND short (attacker doesn't sustain for seconds)
        # Normal streaming is fast but sustained over many seconds
        duration_ms = flow.bidirectional_duration_ms

        if pkt_rate > 500 and flow.bidirectional_packets > 50 and duration_ms < 1000:
            return "DDoS"
        if byte_rate > 500000 and flow.bidirectional_packets > 50 and duration_ms < 1000:
            return "DDoS"


    # ── UDP FLOOD (hping3 --flood -2) ────────────────────
    # Same logic — many flows to same port = flood
    if protocol == 17 and fwd_pkts <= 2 and not is_broadcast:
        if is_scan:
            return "Port Scanning"   # many ports = UDP scan
        if is_flood:
            return "DoS"             # many flows, same port = UDP flood
        return "Normal Traffic"
    

    

    # ── GENERAL HIGH RATE ─────────────────────────────────
    if flow.bidirectional_packets >= 50:   # ← THE GUARD
        if pkt_rate > 3000:
            return "DDoS"
        if pkt_rate > 1000 and avg_size < 100:
            return "DoS"

    # ── BRUTE FORCE ───────────────────────────────────────
    if dst_port in (22, 21, 3389, 23, 25, 110, 143) and pkts > 10 and avg_size < 200:
        return "Brute Force"

    # ── NORMAL ────────────────────────────────────────────
    return "Normal Traffic"


# ─────────────────────────────────────────────
#  FEATURE EXTRACTION
# ─────────────────────────────────────────────
def extract_features(flow) -> dict:

    def safe_div(a, b):
        return float(a) / float(b) if b and b != 0 else 0.0

    def to_us(ms):
        return float(ms) * 1000.0 if ms else 0.0

    duration_s    = max(flow.bidirectional_duration_ms, 1.0) / 1000.0
    HDR           = 20
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
        "Active Mean":                 0.0,
        "Active Max":                  0.0,
        "Active Min":                  0.0,
        "Idle Mean":                   0.0,
        "Idle Max":                    0.0,
        "Idle Min":                    0.0,
    }


# ─────────────────────────────────────────────
#  TERMINAL COLORS & PRINT
# ─────────────────────────────────────────────
COLORS = {
    "Normal Traffic" : "\033[92m",
    "Port Scanning"  : "\033[93m",
    "DoS"            : "\033[91m",
    "DDoS"           : "\033[91m",
    "Brute Force"    : "\033[95m",
}
RESET = "\033[0m"


def print_flow(flow, features, label, flow_num):
    color = COLORS.get(label, "\033[97m")
    ts    = time.strftime("%H:%M:%S")
    proto = "TCP" if flow.protocol == 6 else "UDP"
    ports = len(port_tracker[flow.src_ip])

    print(f"[{ts}] #{flow_num:<5} "
          f"{flow.src_ip:<16} → {flow.dst_ip:<16} "
          f"port={flow.dst_port:<6} "
          f"{proto:<4} "
          f"pkts={flow.bidirectional_packets:<5} "
          f"dur={flow.bidirectional_duration_ms}ms  "
          f"{color}{label}{RESET}  "
          f"[ports seen: {ports}]")

    if label != "Normal Traffic":
        pkts = max(flow.bidirectional_packets, 1)
        print(f"         "
              f"SYN={flow.bidirectional_syn_packets}({flow.bidirectional_syn_packets/pkts:.0%}) "
              f"FIN={flow.bidirectional_fin_packets} "
              f"RST={flow.bidirectional_rst_packets}({flow.bidirectional_rst_packets/pkts:.0%}) "
              f"PSH={flow.bidirectional_psh_packets}({flow.bidirectional_psh_packets/pkts:.0%}) "
              f"ACK={flow.bidirectional_ack_packets} "
              f"→ pkts/s={features['Flow Packets/s']:.0f}  "
              f"bytes/s={features['Flow Bytes/s']:.0f}")


# ─────────────────────────────────────────────
#  MAIN SENSOR LOOP
# ─────────────────────────────────────────────
def run(interface: str):
    print("=" * 75)
    print("  NFStreamer Dataset Collector")
    print("=" * 75)
    print(f"  Interface        : {interface}")
    print(f"  Output           : {CSV_PATH}")
    print(f"  Scan threshold   : {PORT_SCAN_THRESHOLD} unique ports = Port Scanning")
    print(f"                     < {PORT_SCAN_THRESHOLD} unique ports = DoS")
    print(f"\n  Detection rules:")
    print(f"    SYN + no reply + many ports   → Port Scanning")
    print(f"    SYN + no reply + few ports    → DoS")
    print(f"    SYN ratio > 70% + no FIN      → DoS (SYN Flood)")
    print(f"    Web port + PSH rate > 100/s   → DoS (HTTP Flood)")
    print(f"    UDP + pkts/s > 500            → DDoS")
    print(f"    pkts/s > 3000                 → DDoS")
    print(f"    Auth port + small packets     → Brute Force")
    print(f"    Everything else               → Normal Traffic")
    print(f"\n  Press Ctrl+C to stop\n")
    print("─" * 75)

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,
        idle_timeout=60,
        active_timeout=120,
        accounting_mode=1,
    )

    records      = []
    flow_num     = 0
    label_counts = {}

    try:
        for flow in streamer:
            flow_num += 1
            features = extract_features(flow)
            label    = heuristic_label(flow, features)

            label_counts[label] = label_counts.get(label, 0) + 1

            features["Attack Type"] = label
            features["_src_ip"]     = flow.src_ip
            features["_dst_ip"]     = flow.dst_ip
            features["_protocol"]   = flow.protocol
            features["_timestamp"]  = time.strftime("%Y-%m-%d %H:%M:%S")

            records.append(features)
            print_flow(flow, features, label, flow_num)

            if len(records) % 20 == 0:
                batch = records[-20:]   # only the latest 20
                pd.DataFrame(batch).to_csv(
                    CSV_PATH,
                    mode="a",
                    header=not CSV_PATH.exists() or CSV_PATH.stat().st_size == 0,
                    index=False
                )
                print(f"\n  ── appended 20 flows | total={len(records)} | {label_counts} ──\n")

    except KeyboardInterrupt:
        print("\n[!] Capture stopped.")

    finally:
        if records:
            pd.DataFrame(records).to_csv(CSV_PATH, index=False)
            print(f"\n{'='*75}")
            print(f"  Saved {len(records)} flows → {CSV_PATH}")
            print(f"\n  Label distribution:")
            total = sum(label_counts.values())
            for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
                pct = cnt / total * 100
                bar = "█" * min(int(pct), 40)
                color = COLORS.get(lbl, "")
                print(f"    {color}{lbl:<20}{RESET} {cnt:>6} ({pct:5.1f}%)  {bar}")
            print(f"{'='*75}\n")
        else:
            print("[!] No flows captured.")


if __name__ == "__main__":
    run(WIN_INTERFACE)