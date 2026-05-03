import json
import time
from datetime import datetime
from config import JSON_LOG_PATH, ATTACK_CLASSES
from core.heuristic import port_tracker, flow_counter
from api.app import store_log


# ----------------------------
# SAFE HELPERS (IMPORTANT)
# ----------------------------
def safe_str(val, default="N/A"):
    return str(val) if val is not None else default

def safe_int(val, default=0):
    try:
        return int(val)
    except:
        return default

def safe_float(val, default=0.0):
    try:
        return float(val)
    except:
        return default


# ----------------------------
# LOG TO SUPABASE + JSON FILE
# ----------------------------
def log_to_json(flow, features, final_label, dl_label, dl_conf,
                h_label, decided_by, pkt_count):

    src_ip = flow.src_ip or "0.0.0.0"
    dst_ip = flow.dst_ip or "0.0.0.0"

    entry = {
        "timestamp": datetime.now().isoformat(),

        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "dest_port": safe_int(flow.dst_port),
        "protocol": "TCP" if flow.protocol == 6 else "UDP",

        "final_label": final_label,
        "is_attack": final_label in ATTACK_CLASSES,
        "decided_by": decided_by,

        "dl_prediction": dl_label or "Unknown",
        "dl_confidence": safe_float(dl_conf),

        "heuristic_label": h_label or "Unknown",
        "unique_ports_seen": len(port_tracker.get(src_ip, [])),
        "flows_from_ip": flow_counter.get(src_ip, 0),

        "packet_count": pkt_count,
        "pkt_per_sec": safe_float(features.get("Flow Packets/s")),
        "bytes_per_sec": safe_float(features.get("Flow Bytes/s")),
        "duration_ms": safe_int(flow.bidirectional_duration_ms),

        "syn": safe_int(flow.bidirectional_syn_packets),
        "fin": safe_int(flow.bidirectional_fin_packets),
        "rst": safe_int(flow.bidirectional_rst_packets),
        "ack": safe_int(flow.bidirectional_ack_packets),
        "psh": safe_int(flow.bidirectional_psh_packets),
    }

    # Store in Supabase
    store_log(entry)

    # Store locally (JSON backup)
    data = []
    if JSON_LOG_PATH.exists():
        try:
            with open(JSON_LOG_PATH, "r") as f:
                data = json.load(f)
        except:
            data = []

    data.append(entry)

    if len(data) > 5000:
        data = data[-5000:]

    with open(JSON_LOG_PATH, "w") as f:
        json.dump(data, f, indent=2)


# ----------------------------
# COLORS + LABELS
# ----------------------------
COLORS = {
    "Normal Traffic": "\033[92m",
    "Port Scanning":  "\033[93m",
    "DoS":            "\033[91m",
    "DDoS":           "\033[91m",
    "Brute Force":    "\033[95m",
}

RESET = "\033[0m"
CYAN  = "\033[96m"
GRAY  = "\033[90m"

SOURCE_BADGE = {
    "heuristic":          "[H]   ",
    "dl":                 "  [D] ",
    "both":               "[H+M] ",
    "heuristic_fallback": "[H~]  ",
    "dl_fallback":        "  [D~]",
}


# ----------------------------
# SAFE FLOW PRINTER (NO CRASHES)
# ----------------------------
def print_flow(flow, features, final_label, dl_label, dl_conf,
               h_label, decided_by, flow_num):

    color = COLORS.get(final_label, "\033[97m")
    badge = SOURCE_BADGE.get(decided_by, "      ")

    ts = time.strftime("%H:%M:%S")
    proto = "TCP" if flow.protocol == 6 else "UDP"

    src_ip = safe_str(flow.src_ip, "0.0.0.0")
    dst_ip = safe_str(flow.dst_ip, "0.0.0.0")

    dst_port = safe_int(flow.dst_port)
    packets = safe_int(flow.bidirectional_packets)

    ports_seen = len(port_tracker.get(flow.src_ip or "", []))
    dl_conf_safe = safe_float(dl_conf)

    print(
        f"[{ts}] #{safe_int(flow_num):<5} {badge}"
        f"{src_ip:<16} → {dst_ip:<16} "
        f"port={dst_port:<6} {proto:<4} "
        f"pkts={packets:<5} "
        f"{color}{safe_str(final_label):<16}{RESET}"
        f"{GRAY}  dl={safe_str(dl_label)}({dl_conf_safe:.0%})  "
        f"h={safe_str(h_label)}  ports_seen={ports_seen}{RESET}"
    )

    # Attack detail view
    if final_label in ATTACK_CLASSES:
        pkts = max(packets, 1)

        syn = safe_int(flow.bidirectional_syn_packets)
        fin = safe_int(flow.bidirectional_fin_packets)
        rst = safe_int(flow.bidirectional_rst_packets)
        psh = safe_int(flow.bidirectional_psh_packets)

        pkt_rate = safe_float(features.get("Flow Packets/s"))
        byte_rate = safe_float(features.get("Flow Bytes/s"))

        print(
            f"           "
            f"SYN={syn}({syn/pkts:.0%}) "
            f"FIN={fin} "
            f"RST={rst}({rst/pkts:.0%}) "
            f"PSH={psh}({psh/pkts:.0%}) "
            f"→ {pkt_rate:.0f}pkt/s  "
            f"{byte_rate:.0f}B/s"
        )