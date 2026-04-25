from pathlib import Path
import subprocess
import sys
import ctypes
import os
from dotenv import load_dotenv


# it can load all env 
load_dotenv()
# ────────────
# ─────────────────────────────────────────────
#  DYNAMIC PATHING
# ─────────────────────────────────────────────
# Structure: firewall/CICFlowmeter/main.py
#            BASE_DIR = firewall/
# ─────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
OUTPUT_CSV = BASE_DIR / "live_flows.csv"
# Exact NPF ID for "Wi-Fi 2"
INTERFACE  = os.getenv("WIN_INTERFACE")
# ─────────────────────────────────────────────

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

print("=" * 60)
print("  CICFlowMeter Capture — Terminal 1")
print("=" * 60)
if not is_admin():
    print("  [!] WARNING: Not running as Administrator.")
    print("      If capture fails, check Npcap settings.")
print(f"  Interface Name : Wi-Fi 2")
print(f"  Output CSV     : {OUTPUT_CSV}")
print("  Press Ctrl+C to stop capture (and flush to disk)\n")

# Find the cicflowmeter executable inside the venv
VENV_BIN = Path(sys.executable).parent
CIC_EXE  = VENV_BIN / "cicflowmeter.exe"

if not CIC_EXE.exists():
    CIC_EXE = VENV_BIN / "cicflowmeter"

if not CIC_EXE.exists():
    print(f"[ERROR] cicflowmeter executable not found in {VENV_BIN}")
    sys.exit(1)

cmd = [
    str(CIC_EXE),
    "-i", INTERFACE,
    "-c", str(OUTPUT_CSV),
]

print(f"  Running: {' '.join(cmd)}\n")

try:
    subprocess.run(cmd, check=True)
except KeyboardInterrupt:
    print("\n[!] Capture stopped.")
except subprocess.CalledProcessError as e:
    print(f"\n[ERROR] cicflowmeter exited with code {e.returncode}")
    print("  Check: Npcap is installed and interface is correct.")
