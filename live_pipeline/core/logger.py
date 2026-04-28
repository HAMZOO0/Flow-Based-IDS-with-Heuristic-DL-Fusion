import json
import time
from datetime import datetime
from config import JSON_LOG_PATH, ATTACK_CLASSES
from core.heuristic import port_tracker, flow_counter

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

