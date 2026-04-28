from collections import defaultdict
from config import PORT_SCAN_THRESHOLD, FLOOD_FLOW_THRESHOLD

port_tracker = defaultdict(set)   # {src_ip: {dst_port, ...}}
flow_counter = defaultdict(int)   # {src_ip: flow_count}

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




# ── helper: read heuristic label without double-updating counters ──
def peek_heuristic(flow, features: dict) -> str:
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