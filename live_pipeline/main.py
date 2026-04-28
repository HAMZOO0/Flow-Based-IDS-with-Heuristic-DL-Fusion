from collections import defaultdict
from nfstream import NFStreamer
from config import WIN_INTERFACE, ATTACK_CLASSES
from core.features import extract_features
from core.fusion import hybrid_classify
from core.heuristic import peek_heuristic
from core.dl_model import dl_classify
from core.logger import log_to_json, print_flow


def run(interface: str):
    print("Hybrid IDS starting...")
    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,
        idle_timeout=10,
        active_timeout=30,
        accounting_mode=1,
    )

    flow_num      = 0
    label_counts  = defaultdict(int)
    source_counts = defaultdict(int)

    for flow in streamer:
        flow_num += 1
        features = extract_features(flow)

        final_label, final_conf, decided_by = hybrid_classify(flow, features)
        h_label           = peek_heuristic(flow, features)
        dl_label, dl_conf = dl_classify(features)

        label_counts[final_label]  += 1
        source_counts[decided_by]  += 1

        log_to_json(flow, features, final_label,
                    dl_label, dl_conf, h_label, decided_by,
                    flow.bidirectional_packets)

        print_flow(flow, features, final_label,
                   dl_label, dl_conf, h_label, decided_by, flow_num)


if __name__ == "__main__":
    run(WIN_INTERFACE)