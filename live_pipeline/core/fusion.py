from config import DL_CONFIDENCE_MIN
from core.heuristic import heuristic_label
from core.dl_model import dl_classify

#  ═══════════════════════════════════════════════════════════════
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
# from live_pipeline.core.heuristic import heuristic_label


def hybrid_classify(flow, features: dict):
    h_label              = heuristic_label(flow, features) # we use heuristic_label function to get the label from heuristic module and we will use this label in our fusion logic


    dl_label, dl_conf    = dl_classify(features) # we use dl to get the label and confidence score



    # Rule 1 — heuristic is the only thing that can catch scans
    if h_label == "Port Scanning":
        return "Port Scanning", 1.0, "heuristic"

    # Rule 2 — attack types DL was never trained on | we are not  detecting Brute Force 
    if h_label in ("Brute Force", "DDoS"):
        return h_label, 1.0, "heuristic"

    # Rule 3 — high-confidence DL prediction
    if dl_conf >= DL_CONFIDENCE_MIN: # 80% confidence or higher → trust DL
        return dl_label, dl_conf, "dl"

    # Rule 4 — both layers agree (even at lower confidence)
    if h_label == dl_label:
        return dl_label, dl_conf, "both"

    # Rule 5 — heuristic says attack, DL is uncertain → trust heuristic
    if h_label != "Normal Traffic":
        return h_label, dl_conf, "heuristic_fallback"

    # Rule 6 — default to DL result
    return dl_label, dl_conf, "dl_fallback"