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


 