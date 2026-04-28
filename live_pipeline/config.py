# from curses.ascii import SYN
import os
# import sys
# import time
# import json
# import torch
# import joblib
import warnings
# import numpy as np
# import pandas as pd
# import torch.nn as nn
# from datetime import datetime
from pathlib import Path
# from collections import defaultdict
# from nfstream import NFStreamer
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
