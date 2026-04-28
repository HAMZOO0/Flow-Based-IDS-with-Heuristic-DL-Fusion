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
