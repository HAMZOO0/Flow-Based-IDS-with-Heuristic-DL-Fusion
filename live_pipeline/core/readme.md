# 🧠 DDoS Sentinel Core Logic

This directory contains the heart of the detection engine. It uses a **Hybrid Fusion** approach, combining traditional rule-based heuristics with modern Deep Learning.

## 🏗️ Core Components

### 1. 🔍 Heuristic Engine (`heuristic.py`)
The heuristic engine is the first line of defense. It tracks cross-flow patterns that a single-flow classifier cannot see.
- **Port Scan Detection**: Tracks unique destination ports per source IP. If `unique_ports >= 20`, it triggers a Port Scanning alert.
- **SYN Flood Detection**: Monitors SYN/FIN ratios and packet rates.
- **HTTP Flood Detection**: Analyzes PSH flag ratios and request/response imbalances on web ports (80, 443).
- **UDP DDoS**: Detects high-rate UDP floods with short durations.

### 2. 🤖 Deep Learning Model (`dl_model.py`)
A PyTorch-based Multi-Layer Perceptron (MLP) trained on a massive dataset of DoS and Normal traffic.
- **Input**: 50+ statistical flow features (extracted via NFStreamer).
- **Architecture**: `128 (ReLU) -> 64 (ReLU) -> N (Softmax)`.
- **Confidence Scoring**: Only labels with $\ge 80\%$ confidence are trusted by default.

### 3. ⚖️ Hybrid Fusion (`fusion.py`)
The "Brain" that decides which engine to trust for each flow.

| Priority | Logic | Decision Source |
| :--- | :--- | :--- |
| **1** | Heuristic detects Port Scan | `heuristic` |
| **2** | Heuristic detects Brute Force / DDoS | `heuristic` |
| **3** | DL Confidence $\ge 80\%$ | `dl` |
| **4** | Both Engines Agree | `both` |
| **5** | Heuristic says Attack, DL uncertain | `heuristic_fallback` |
| **6** | Default to DL | `dl_fallback` |

### 4. 📊 Logger (`logger.py`)
Handles real-time terminal visualization and JSON logging.
- **Terminal**: Color-coded output with badges (`[H]`, `[D]`, `[H+D]`) indicating the decision source.
- **JSON**: Rich structured data exported to `ids_logs.json` for dashboard consumption.

## 🛠️ Feature Extraction
The `features.py` module maps raw **NFStreamer** flows into the 50-feature vector required by the DL model, ensuring consistency between training and live inference.
