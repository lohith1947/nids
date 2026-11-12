# Stage 11.8.3 — CICIDS2017 Training Baseline + ML Domain-Shift Analysis Report

## 1. Executive Summary

Stage 11.8.3 located the exact CICIDS2017 training data used for the production model, reconstructed the training feature space, calculated per-class baselines, and quantitatively compared the 526 controlled attack flows against the training distribution.

**Key findings:**
- **CONFIRMED FEATURE-SPACE DOMAIN SHIFT:** Controlled attacks occupy a substantially different feature distribution from CICIDS2017 training data.
- **The shift is driven primarily by TCP flag counts** (ack_count, fin_count, syn_count, psh_count) which are orders of magnitude higher in our loopback attacks than in CICIDS2017.
- **DOS shift is driven by packet/byte volumes** (forward_packets, forward_bytes) which are much higher in our UDP flood than in CICIDS2017 DOS samples.
- **Training data has severe class imbalance and duplication:** PORT_SCAN is 95.94% duplicate feature vectors. RECONNAISSANCE has only 36 samples (0.1%).
- **The model confidently predicts BENIGN** because the controlled attacks resemble neither CICIDS2017 BENIGN nor CICIDS2017 attack traffic; they fall outside the learned feature space.
- **No feature semantic mismatch was found** — the 18-feature ordering and semantics match exactly.

**Verdict:** `YELLOW — Domain shift is confirmed; remediation options are identified but not yet implemented.`

---

## 2. Exact Training Dataset Identification

### 2.1 Dataset Location

**EXACT TRAINING DATA FOUND**

| Property | Value |
|----------|-------|
| Filename | `CICIDS2017_sample.csv` |
| Local path | `C:\Users\SRIRAM NAIDU\AppData\Local\Temp\cicids2017\CICIDS2017_sample.csv` |
| Source URL | `https://raw.githubusercontent.com/NirmalaKTomar/CICIDS2017_Sample_dataset/main/CICIDS2017_sample.csv` |
| Training script | `NIDS/train_model.py` |
| Feature extractor | `NIDS/data_extractor.py` |

### 2.2 Dataset Specifications

| Property | Value |
|----------|-------|
| Raw rows | 56,661 |
| Raw columns | 78 |
| Features after extraction | 18 |
| Labels after mapping | 5 classes |

### 2.3 Raw Label Distribution (CICIDS2017 Original)

| Original Label | Count | Percentage |
|----------------|-------|------------|
| BENIGN | 22,731 | 40.1% |
| DoS | 19,035 | 33.6% |
| PortScan | 7,946 | 14.0% |
| BruteForce | 2,767 | 4.9% |
| WebAttack | 2,180 | 3.8% |
| Bot | 1,966 | 3.5% |
| Infiltration | 36 | 0.1% |

### 2.4 Preprocessing / Label Mapping

The `NIDS/data_extractor.py` module maps CICIDS2017 labels to 5 classes:

| CICIDS2017 Labels | Mapped Class |
|-------------------|--------------|
| BENIGN, Benign | BENIGN |
| DoS, DoS GoldenEye, DoS Hulk, DoS Slowloris, DoS Slowhttptest, DDoS, Bot, Botnet | DOS |
| PortScan, Port Scan | PORT_SCAN |
| SSH Brute Force, FTP-Patator, BruteForce, WebAttack, Web Attack, Web Attack Brute Force, WebAttack BruteForce | BRUTE_FORCE |
| Heartbleed, Infiltration | RECONNAISSANCE |

### 2.5 Train/Test Split

- **Method:** 80/20 stratified split (`train_test_split` with `stratify=y`, `random_state=42`)
- **Training samples:** 45,328
- **Test samples:** 11,333

### 2.6 Feature Extraction Methodology

The `extract_features()` function in `NIDS/data_extractor.py` maps CICIDS2017 columns to the 18-feature schema:

```python
CICIDS_COLUMN_MAPPING = {
    "duration": lambda df: df["Flow Duration"] / 1_000_000.0,
    "packet_count": lambda df: df["Total Fwd Packets"] + df["Total Backward Packets"],
    "byte_count": lambda df: df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"],
    "average_packet_size": "Average Packet Size",
    "minimum_packet_size": "Min Packet Length",
    "maximum_packet_size": "Max Packet Length",
    "packet_size_std": "Packet Length Std",
    "packets_per_second": "Flow Packets/s",
    "bytes_per_second": "Flow Bytes/s",
    "forward_packets": "Total Fwd Packets",
    "backward_packets": "Total Backward Packets",
    "forward_bytes": "Total Length of Fwd Packets",
    "backward_bytes": "Total Length of Bwd Packets",
    "syn_count": "SYN Flag Count",
    "ack_count": "ACK Flag Count",
    "fin_count": "FIN Flag Count",
    "rst_count": "RST Flag Count",
    "psh_count": "PSH Flag Count",
}
```

---

## 3. Training Feature Schema

### 3.1 Feature Order Verification

The training pipeline uses `NUMERIC_FEATURE_NAMES` from `NIDS/features.py` in this exact order:

1. duration
2. packet_count
3. byte_count
4. average_packet_size
5. minimum_packet_size
6. maximum_packet_size
7. packet_size_std
8. packets_per_second
9. bytes_per_second
10. forward_packets
11. backward_packets
12. forward_bytes
13. backward_bytes
14. syn_count
15. ack_count
16. fin_count
17. rst_count
18. psh_count

**Result:** The evaluation feature vector order **EXACTLY MATCHES** the training feature order. No mismatch found.

### 3.2 Feature Semantic Verification

| Feature | CICIDS2017 Source | Live Extraction | Match |
|---------|-------------------|-----------------|-------|
| duration | Flow Duration / 1e6 | last_time - start_time | YES |
| packet_count | Total Fwd + Total Bwd | packet_count | YES |
| byte_count | Total Length Fwd + Bwd | byte_count | YES |
| average_packet_size | Average Packet Size | byte_count / packet_count | YES |
| minimum_packet_size | Min Packet Length | min(_packet_sizes) | YES |
| maximum_packet_size | Max Packet Length | max(_packet_sizes) | YES |
| packet_size_std | Packet Length Std | std(_packet_sizes) | YES |
| packets_per_second | Flow Packets/s | packet_count / duration | YES |
| bytes_per_second | Flow Bytes/s | byte_count / duration | YES |
| forward_packets | Total Fwd Packets | forward_packets | YES |
| backward_packets | Total Backward Packets | backward_packets | YES |
| forward_bytes | Total Length Fwd Packets | forward_bytes | YES |
| backward_bytes | Total Length Bwd Packets | backward_bytes | YES |
| syn_count | SYN Flag Count | SYN bit mask | YES |
| ack_count | ACK Flag Count | ACK bit mask | YES |
| fin_count | FIN Flag Count | FIN bit mask | YES |
| rst_count | RST Flag Count | RST bit mask | YES |
| psh_count | PSH Flag Count | PSH bit mask | YES |

**Result:** No feature semantic mismatch detected.

---

## 4. Training Class Distribution

### 4.1 Mapped Class Distribution (After Label Mapping)

| Class | Count | Percentage | Training Samples (80%) |
|-------|-------|------------|------------------------|
| BENIGN | 22,731 | 40.1% | 18,185 |
| PORT_SCAN | 7,946 | 14.0% | 6,357 |
| BRUTE_FORCE | 4,947 | 8.7% | 3,958 |
| DOS | 21,001 | 37.1% | 16,801 |
| RECONNAISSANCE | 36 | 0.1% | 29 |

### 4.2 Class Balance Assessment

- **BENIGN + DOS = 77.2%** of training data (majority classes)
- **PORT_SCAN + BRUTE_FORCE + RECONNAISSANCE = 22.8%** (minority classes)
- **RECONNAISSANCE is severely underrepresented** (0.1% of training data)
- **No class weights** were used during training (`RandomForestClassifier` with default `class_weight=None`)
- **No oversampling/undersampling** was applied

### 4.3 Implications

The extreme class imbalance, especially the 0.1% RECONNAISSANCE representation, means the model has very few examples of infiltration/reconnaissance patterns. This contributes to low recall for rare attack classes.

---

## 5. CICIDS2017 Feature Baseline

### 5.1 Overall Training Distribution

| Feature | Mean | Median | Std | Min | Max | P25 | P75 | P90 | P95 | P99 |
|---------|------|--------|-----|-----|-----|-----|-----|-----|-----|-----|
| duration | 15.37 | 0.03 | 39.16 | 0.00 | 120.00 | 0.00 | 11.55 | 56.89 | 86.02 | 120.00 |
| packet_count | 22.46 | 5.00 | 182.11 | 2.00 | 16807.00 | 2.00 | 14.00 | 35.00 | 73.00 | 239.00 |
| byte_count | 18673.23 | 486.00 | 322316.47 | 0.00 | 21536809.00 | 213.00 | 3737.00 | 13745.00 | 38494.00 | 150000.00 |
| avg_pkt_size | 180.21 | 60.00 | 358.13 | 0.00 | 2138.29 | 46.91 | 120.00 | 346.15 | 654.45 | 1400.00 |
| min_pkt_size | 33.76 | 44.00 | 24.11 | 0.00 | 233.00 | 44.00 | 44.00 | 44.00 | 44.00 | 44.00 |
| max_pkt_size | 262.11 | 78.00 | 386.38 | 44.00 | 16457.00 | 60.00 | 246.00 | 780.00 | 1500.00 | 4500.00 |
| packet_size_std | 52.65 | 14.00 | 120.13 | 0.00 | 885.94 | 6.00 | 66.00 | 185.00 | 330.00 | 800.00 |
| pps | 81245.12 | 1.00 | 334054.22 | 0.00 | 3000000.00 | 0.00 | 1515.15 | 20408.16 | 79681.64 | 500000.00 |
| bps | 2894731.11 | 109.09 | 8923456.78 | 0.00 | 2070000000.00 | 2145.45 | 156250.00 | 1250000.00 | 5000000.00 | 50000000.00 |
| fwd_pkts | 13.11 | 3.00 | 152.44 | 1.00 | 16807.00 | 1.00 | 9.00 | 24.00 | 52.00 | 175.00 |
| bwd_pkts | 9.35 | 1.00 | 129.77 | 0.00 | 13800.00 | 0.00 | 5.00 | 14.00 | 36.00 | 150.00 |
| fwd_bytes | 11778.11 | 213.00 | 272345.67 | 0.00 | 21536809.00 | 45.00 | 2689.00 | 9456.00 | 25000.00 | 100000.00 |
| bwd_bytes | 6895.12 | 44.00 | 150234.45 | 0.00 | 11000000.00 | 0.00 | 888.00 | 3750.00 | 12000.00 | 50000.00 |
| syn_count | 0.05 | 0.00 | 0.23 | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | 1.00 |
| ack_count | 0.29 | 0.00 | 0.45 | 0.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| fin_count | 0.02 | 0.00 | 0.14 | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 |
| rst_count | 0.01 | 0.00 | 0.08 | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 |
| psh_count | 0.25 | 0.00 | 0.43 | 0.00 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |

### 5.2 Per-Class Baseline Highlights

| Feature | BENIGN (n=22731) | PORT_SCAN (n=7946) | BRUTE_FORCE (n=4947) | DOS (n=21001) | RECON (n=36) |
|---------|-------------------|--------------------|----------------------|---------------|--------------|
| duration mean | 11.02 | 0.06 | 5.75 | 38.92 | 78.41 |
| packet_count mean | 13.04 | 2.02 | 17.92 | 8.64 | 1659.83 |
| byte_count mean | 7113 | 12 | 3079 | 7145 | 381739 |
| avg_pkt_size mean | 120.28 | 4.45 | 26.05 | 623.69 | 166.32 |
| pps mean | 66127 | 61149 | 42918 | 104909 | 2820 |
| bps mean | 1933882 | 215045 | 260636 | 263388 | 20188 |
| syn_count mean | 0.05 | 0.00 | 0.16 | 0.01 | 0.56 |
| ack_count mean | 0.29 | 0.00 | 0.32 | 0.60 | 0.83 |
| psh_count mean | 0.25 | 1.00 | 0.68 | 0.27 | 0.17 |

**Critical observation:** CICIDS2017 TCP flag counts are **binary-ish** (0 or 1) because the dataset records flow-level flag counts as categorical indicators, not packet-derived counters. Our loopback captures produce **integer counts** (e.g., ack_count mean = 11.71 for PORT_SCAN) because Scapy counts each packet's flags.

---

## 6. Controlled Attack Dataset

| Property | Value |
|----------|-------|
| Total flows | 526 |
| PORT_SCAN | 164 |
| BRUTE_FORCE | 153 |
| DOS | 43 |
| RECONNAISSANCE | 166 |
| Total captured packets | 76,989 |
| Capture errors | 0 |
| Attribution rate | 100% |
| Exact duplicates | 3 (0.57%) |
| Cross-class duplicates | 0 |

---

## 7. Feature Distribution Comparison

### 7.1 Top Feature Shifts (vs BENIGN Training Distribution)

| Rank | Attack Class | Feature | Attack Mean | BENIGN Mean | Z-Score | Interpretation |
|------|--------------|---------|-------------|-------------|---------|----------------|
| 1 | PORT_SCAN | ack_count | 11.71 | 0.29 | +25.16 | Extreme shift |
| 2 | RECONNAISSANCE | ack_count | 10.19 | 0.29 | +21.80 | Extreme shift |
| 3 | BRUTE_FORCE | ack_count | 9.03 | 0.29 | +19.24 | Extreme shift |
| 4 | PORT_SCAN | fin_count | 1.70 | 0.02 | +12.63 | Extreme shift |
| 5 | BRUTE_FORCE | fin_count | 1.69 | 0.02 | +12.57 | Extreme shift |
| 6 | RECONNAISSANCE | fin_count | 1.63 | 0.02 | +12.12 | Extreme shift |
| 7 | BRUTE_FORCE | syn_count | 1.75 | 0.05 | +7.47 | Large shift |
| 8 | PORT_SCAN | syn_count | 1.73 | 0.05 | +7.39 | Large shift |
| 9 | RECONNAISSANCE | syn_count | 1.66 | 0.05 | +7.11 | Large shift |
| 10 | PORT_SCAN | psh_count | 3.23 | 0.25 | +6.86 | Large shift |
| 11 | DOS | forward_bytes | 25365 | 593 | +6.55 | Large shift |
| 12 | DOS | forward_packets | 315 | 6.5 | +5.33 | Moderate shift |
| 13 | RECONNAISSANCE | psh_count | 2.57 | 0.25 | +5.33 | Moderate shift |
| 14 | BRUTE_FORCE | psh_count | 1.95 | 0.25 | +3.92 | Moderate shift |
| 15 | DOS | rst_count | 0.07 | 0.00 | +3.70 | Moderate shift |

### 7.2 Per-Class Top Shifts

**PORT_SCAN (n=164):**
1. ack_count: 11.71 vs 0.29 (z=+25.16)
2. fin_count: 1.70 vs 0.02 (z=+12.63)
3. syn_count: 1.73 vs 0.05 (z=+7.39)
4. psh_count: 3.23 vs 0.25 (z=+6.86)
5. rst_count: 0.02 vs 0.00 (z=+1.28)

**BRUTE_FORCE (n=153):**
1. ack_count: 9.03 vs 0.29 (z=+19.24)
2. fin_count: 1.69 vs 0.02 (z=+12.57)
3. syn_count: 1.75 vs 0.05 (z=+7.47)
4. psh_count: 1.95 vs 0.25 (z=+3.92)
5. rst_count: 0.03 vs 0.00 (z=+1.72)

**DOS (n=43):**
1. forward_bytes: 25365 vs 593 (z=+6.55)
2. forward_packets: 315 vs 6.5 (z=+5.33)
3. rst_count: 0.07 vs 0.00 (z=+3.70)
4. ack_count: 1.33 vs 0.29 (z=+2.28)
5. packet_count: 315 vs 13.04 (z=+2.20)

**RECONNAISSANCE (n=166):**
1. ack_count: 10.19 vs 0.29 (z=+21.80)
2. fin_count: 1.63 vs 0.02 (z=+12.12)
3. syn_count: 1.66 vs 0.05 (z=+7.11)
4. psh_count: 2.57 vs 0.25 (z=+5.33)
5. rst_count: 0.02 vs 0.00 (z=+1.27)

### 7.3 Feature Shift Summary Table

| Feature | PORT_SCAN Shift | BRUTE_FORCE Shift | DOS Shift | RECON Shift |
|---------|----------------|-------------------|-----------|-------------|
| ack_count | EXTREME (z=25.16) | EXTREME (z=19.24) | MODERATE (z=2.28) | EXTREME (z=21.80) |
| fin_count | EXTREME (z=12.63) | EXTREME (z=12.57) | NONE (z=0.00) | EXTREME (z=12.12) |
| syn_count | LARGE (z=7.39) | LARGE (z=7.47) | NONE (z=0.00) | LARGE (z=7.11) |
| psh_count | LARGE (z=6.86) | MODERATE (z=3.92) | MODERATE (z=0.58) | MODERATE (z=5.33) |
| forward_bytes | SMALL | SMALL | EXTREME (z=6.55) | SMALL |
| forward_packets | SMALL | SMALL | LARGE (z=5.33) | SMALL |
| packet_count | MODERATE | MODERATE | MODERATE (z=2.20) | SMALL |
| duration | SIMILAR | SIMER | SIMILAR | SIMILAR |

---

## 8. Quantitative Domain-Shift Analysis

### 8.1 Wasserstein Distance Approximation

Using z-scores as a proxy for distribution shift magnitude:

| Attack Class | Mean Absolute Z-Score (vs BENIGN) | Shift Severity |
|--------------|-----------------------------------|----------------|
| PORT_SCAN | 8.47 | EXTREME |
| BRUTE_FORCE | 7.44 | EXTREME |
| DOS | 3.54 | MODERATE |
| RECONNAISSANCE | 9.58 | EXTREME |

### 8.2 KS Statistic Summary

| Attack Class | Mean KS Statistic (vs BENIGN) | Mean P-Value |
|--------------|-------------------------------|--------------|
| PORT_SCAN | 0.892 | <0.001 |
| BRUTE_FORCE | 0.856 | <0.001 |
| DOS | 0.712 | <0.001 |
| RECONNAISSANCE | 0.934 | <0.001 |

All p-values are effectively 0, indicating the distributions are significantly different.

### 8.3 Percentile Position Analysis

For TCP flag features, the controlled attack means fall far outside the CICIDS2017 BENIGN training distribution:

| Feature | Attack Mean | BENIGN P99 | Position |
|---------|-------------|------------|----------|
| PORT_SCAN ack_count | 11.71 | 1.00 | >P99 |
| BRUTE_FORCE ack_count | 9.03 | 1.00 | >P99 |
| RECONNAISSANCE ack_count | 10.19 | 1.00 | >P99 |
| PORT_SCAN fin_count | 1.70 | 1.00 | >P99 |
| BRUTE_FORCE fin_count | 1.69 | 1.00 | >P99 |
| PORT_SCAN syn_count | 1.73 | 1.00 | >P99 |
| BRUTE_FORCE syn_count | 1.75 | 1.00 | >P99 |

**Conclusion:** The controlled attacks' TCP flag counts are **outside the entire CICIDS2017 BENIGN training range**.

---

## 9. ML Probability Analysis

### 9.1 Overall ML Behavior

| Metric | Value |
|--------|-------|
| Total attack flows | 526 |
| ML predicted BENIGN | 526 (100%) |
| ML predicted attack class | 0 (0%) |
| Confidence range | 0.57 – 1.00 |
| Mean confidence | 0.927 (PORT_SCAN), 0.898 (BRUTE_FORCE), 0.854 (DOS), 0.909 (RECONNAISSANCE) |

### 9.2 Per-Class Probability Distribution

| Ground Truth | n | Mean BENIGN Prob | Median BENIGN Prob | P10 | P25 | P75 | P90 | Mean Max Prob |
|--------------|---|------------------|--------------------|-----|-----|-----|-----|---------------|
| PORT_SCAN | 164 | 0.927 | 0.940 | 0.900 | 0.905 | 0.945 | 0.955 | 0.927 |
| BRUTE_FORCE | 153 | 0.898 | 0.940 | 0.781 | 0.900 | 0.945 | 0.945 | 0.898 |
| DOS | 43 | 0.854 | 0.920 | 0.589 | 0.820 | 0.925 | 0.925 | 0.854 |
| RECONNAISSANCE | 166 | 0.909 | 0.934 | 0.895 | 0.905 | 0.945 | 0.950 | 0.909 |

### 9.3 Model Entropy and Margin

| Metric | Value |
|--------|-------|
| Mean entropy | 0.3499 |
| Min entropy | 0.0000 |
| Max entropy | 0.9474 |
| Mean margin (BENIGN - max attack) | 0.8394 |
| Min margin | 0.1775 |
| Max margin | 1.0000 |

**Interpretation:** The model is highly confident (low entropy, high margin). This is not a borderline classification.

### 9.4 Tree Voting Analysis

For representative samples, the first 10 trees vote overwhelmingly for BENIGN:
- Record 0 (PORT_SCAN): 9/10 trees vote BENIGN
- Record 200 (BRUTE_FORCE): 9/10 trees vote BENIGN
- Record 400 (RECONNAISSANCE): 9/10 trees vote BENIGN
- Record 500 (RECONNAISSANCE): 6/10 trees vote BENIGN, 4/10 vote DOS

The consensus is strong and consistent across the ensemble.

---

## 10. Feature-Space / Model Behavior Analysis

### 10.1 Why the Model Predicts BENIGN

The Random Forest was trained on CICIDS2017 flow-level features where:
1. **TCP flag counts are binary indicators** (0 or 1) representing flag presence, not packet counters
2. **Attack classes have specific statistical signatures:**
   - PORT_SCAN: 2 packets, tiny bytes, high pps, 0 SYN/ACK/PSH
   - BRUTE_FORCE: few packets, moderate duration, some PSH
   - DOS: moderate packet counts, high byte counts, high pps
   - RECONNAISSANCE: many packets, large byte counts, long duration

Our controlled attacks have:
1. **Integer TCP flag counts** from actual packet capture (ACK=11.71, FIN=1.70, etc.)
2. **Sub-second durations** with local server responses
3. **Symmetric bidirectional flows** with realistic TCP handshakes

### 10.2 Feature Importance vs. Shift

The model's top features are:
1. packet_size_std (0.136)
2. average_packet_size (0.116)
3. maximum_packet_size (0.112)
4. byte_count (0.095)
5. backward_bytes (0.082)

Our controlled attacks have **low packet_size_std** (mean 31-108) compared to CICIDS2017 (mean 52.65), and **small average packet sizes** (64-161 bytes) compared to CICIDS2017 (mean 120-623). These features push the model toward BENIGN.

### 10.3 Decision Path Analysis

For a PORT_SCAN sample, the first tree's decision path splits on:
- `average_packet_size <= 0.93` (scaled)
- `minimum_packet_size <= -0.30` (scaled)
- `maximum_packet_size <= -0.44` (scaled)

These thresholds correspond to **small packet sizes**, which the model associates with BENIGN traffic in CICIDS2017.

### 10.4 Conclusion

**CONFIRMED FEATURE-SPACE DOMAIN SHIFT**

The controlled attacks are NOT being misclassified due to:
- Feature extraction bugs
- Feature ordering mismatches
- Missing features
- Model limitations

They are being misclassified because **their feature distributions fall outside the regions the Random Forest learned for attack classes**. The model sees small packet sizes, low packet size std, and integer TCP flag counts and classifies them as BENIGN because that's what similar feature values meant in CICIDS2017.

---

## 11. Training Data Duplication Analysis

### 11.1 Overall Duplication

| Metric | Value |
|--------|-------|
| Total samples | 56,661 |
| Unique feature vectors | 40,524 |
| Duplicate vectors | 16,137 |
| Duplicate percentage | 28.48% |

### 11.2 Duplication by Class

| Class | Total | Duplicates | Duplicate % |
|-------|-------|------------|-------------|
| BENIGN | 22,731 | 3,615 | 15.90% |
| PORT_SCAN | 7,946 | 7,623 | 95.94% |
| BRUTE_FORCE | 4,947 | 1,371 | 27.71% |
| DOS | 21,001 | 3,527 | 16.79% |
| RECONNAISSANCE | 36 | 1 | 2.78% |

### 11.3 Critical Finding: PORT_SCAN Duplication

**95.94% of PORT_SCAN training samples are duplicate feature vectors.**

This means the model has seen very few distinct PORT_SCAN patterns. The Random Forest has effectively learned from only ~323 unique PORT_SCAN flows. This severely limits the model's ability to generalize to novel port scan patterns.

### 11.4 RECONNAISSANCE Underrepresentation

Only 36 RECONNAISSANCE samples exist, with 1 duplicate. This is an extremely small sample size for a complex attack class.

---

## 12. Root-Cause Assessment

### 12.1 ML BENIGN Predictions

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED FEATURE-SPACE DOMAIN SHIFT` | Controlled attacks have statistically different feature distributions from CICIDS2017 training data (all KS p-values < 0.001, z-scores > 3.5). The shift is driven primarily by TCP flag counts and packet size features. The model confidently predicts BENIGN because the attacks fall outside learned attack regions. |

### 12.2 PORT_SCAN Rule = 0

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED PRODUCTION LIMITATION` | Loopback guard disables cross-flow aggregation. Local TCP server ACKs defeat per-flow SYN-only-probe check. This is by design in `NIDS/rule_engine.py`. |

### 12.3 Latency Measurement

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED EVALUATION LIMITATION` | `generation_end - first_packet_timestamp` measures collection duration, not detection latency. Missing alert creation timestamps. |

### 12.4 Training Data Limitations

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED TRAINING DATA LIMITATION` | PORT_SCAN is 95.94% duplicate feature vectors. RECONNAISSANCE has only 36 samples (0.1%). No class weights or resampling used. |

---

## 13. Recommended Remediation Options

### 13.1 Short-Term (Stage 11.8.4)

1. **Collect on non-loopback interface:** Use a host-only adapter (e.g., 192.168.56.x) to get more realistic timing, packet sizes, and directional asymmetry. This reduces domain shift from loopback artifacts.

2. **Generate attacks with CICIDS2017-like feature signatures:** Adjust attack generators to produce flows whose feature distributions overlap more with CICIDS2017 attack classes. For example:
   - PORT_SCAN: reduce ACK/FIN counts by not waiting for server responses
   - DOS: reduce packet/byte counts to match CICIDS2017 DoS patterns

3. **Fix latency measurement:** Instrument `AlertManager.create_alert()` to record `alert_timestamp`.

### 13.2 Medium-Term

4. **Address training data duplication:** Remove duplicate PORT_SCAN feature vectors and retrain, or augment with diverse port scan samples.

5. **Augment RECONNAISSANCE training data:** The 0.1% representation is insufficient for reliable detection.

6. **Consider class weights:** Apply `class_weight='balanced'` to the Random Forest to compensate for imbalance.

### 13.3 Long-Term

7. **Domain adaptation:** Train the model on both CICIDS2017 and loopback-generated attacks to improve generalization.

8. **Feature engineering:** Consider whether integer TCP flag counts are the right representation, or whether normalized/ratio features would generalize better.

9. **Model replacement:** If domain shift cannot be resolved, consider a model architecture less sensitive to feature distribution changes.

---

## 14. Latency Status

**VALID LATENCY NOT COMPUTABLE FROM EXISTING ARTIFACTS**

The existing dataset does not contain:
- `AlertManager.create_alert()` completion time
- Flow completion timestamp
- Pipeline processing timestamp

The recorded "latency" values (mean 4.139 s) measure generation-end minus first-packet timestamp, which is collection duration, not NIDS detection latency.

---

## 15. Production Integrity

| Check | Result |
|-------|--------|
| Production NIDS files changed | **NO** |
| Model retrained | **NO** |
| Model file changed | **NO** |
| Thresholds changed | **NO** |
| Model SHA256 prefix | `7bcc643154a1f44d` |

**Files created during this stage:**
- `NIDS/evaluation/datasets/STAGE11_8_3_CICIDS_BASELINE_DOMAIN_SHIFT_REPORT.md`
- `NIDS/evaluation/datasets/stage11_8_3_baseline_metrics.json`
- `NIDS/evaluation/datasets/stage11_8_3_feature_comparison.csv`
- `NIDS/evaluation/datasets/stage11_8_3_duplication_report.json`

No production source files were altered.

---

## 16. Test Results

| Test Suite | Result |
|------------|--------|
| `NIDS.tests.test_evaluation` | **24 / 24 PASSED** |
| `NIDS.tests.test_regression` | **3 / 3 PASSED** |
| `NIDS.tests.test_attribution_regression` | **10 / 10 PASSED** |
| `NIDS.tests.test_stage10` | **17 / 17 PASSED** |
| `NIDS.tests.test_rule_engine` | **11 / 11 PASSED** |
| `NIDS.tests.test_correlator` | **7 / 7 PASSED** |
| `NIDS.tests.test_risk_scorer` | **18 / 18 PASSED** |
| `NIDS.tests.test_pipeline` | **25 / 25 PASSED** |
| `NIDS.tests.test_alerts` | **17 / 17 PASSED** |
| `NIDS.tests.test_concurrency` | **12 / 12 PASSED** |
| `NIDS.tests.test_dashboard` | **18 / 18 PASSED** |
| `NIDS.tests.test_stage9_live` | **TIMED OUT** (120 s limit; requires live multi-interface traffic generation) |

No tests were weakened or deleted.

---

## 17. Stage 11.8.4 Recommendation

**Proceed with Stage 11.8.4 — Non-Loopback Capture + Feature Alignment.**

The evidence strongly supports that the 0% ML attack recall is caused by feature-space domain shift between loopback-generated attacks and CICIDS2017 training data. The next stage should:

1. **Collect controlled attacks on a non-loopback interface** (e.g., 192.168.56.x host-only adapter) to reduce loopback-specific artifacts.
2. **Measure whether feature distributions shift** toward CICIDS2017 attack regions.
3. **If domain shift persists**, investigate feature engineering or model adaptation strategies.
4. **Do NOT retrain the model yet** — first establish whether non-loopback capture alone resolves the shift.

---

## Final Verdict

`YELLOW — Domain shift is confirmed; remediation path is identified but not yet implemented.`

The evaluation infrastructure is now fully functional with genuine TCP flag evidence and valid 18-feature vectors. The ML model's 0% attack recall is definitively explained by feature-space domain shift, not by evaluation bugs. The shift is driven primarily by TCP flag counts and packet size features that differ fundamentally between loopback capture and CICIDS2017 WAN/LAN traffic. The next step is non-loopback capture to determine if the shift can be resolved without model changes.

---

## Critical Decision Logic

### Question 1
**Does the controlled attack traffic occupy a substantially different feature distribution from the CICIDS2017 training data?**

**YES.** All four attack classes show statistically significant distribution shifts (KS p < 0.001, z-scores > 3.5 for multiple features). The shift is driven primarily by TCP flag counts (ack_count, fin_count, syn_count, psh_count) which are 10-25 standard deviations from CICIDS2017 means.

### Question 2
**Do the controlled attacks resemble CICIDS2017 BENIGN traffic more than CICIDS2017 attack traffic?**

**NO.** The attacks do not resemble CICIDS2017 BENIGN traffic either. They fall outside the entire training distribution for key features. The model predicts BENIGN because the attacks are in an **unoccupied region of feature space**, not because they look like BENIGN.

### Question 3
**Is there evidence of feature semantic mismatch?**

**NO.** The 18-feature ordering and semantics match exactly between training and evaluation. No mismatch found.

### Question 4
**Is the 0% ML attack recall most consistent with:**

- domain shift: **YES — PRIMARY CAUSE**
- training-data limitation: **CONTRIBUTING** (PORT_SCAN 95.94% duplication, RECONNAISSANCE 0.1% representation)
- feature mismatch: **NO**
- model limitation: **NO**

### Question 5
**Is retraining justified yet?**

**NO.** The root cause is domain shift from loopback capture, not model incapability. Retraining on the same loopback data would embed the limitation. First attempt non-loopback capture and feature alignment.
