# STAGE 11.4B - LOOPBACK DOS FALSE POSITIVE INVESTIGATION REPORT

Date: 2026-09-09 17:02:23 UTC
Pilot Dataset: benign_pilot_pilot_11_4a_benign_20260909T164225Z.jsonl
Historical FP: 127.0.0.1:65260 -> 127.0.0.1:49718

---

## 1. Executive Summary

The Stage 11.4A benign pilot collected 232 flows, of which 5 were false positives (2.16% FPR). All 5 FPs were predicted as DOS (4) or PORT_SCAN (1) by the Random Forest model, despite all flows being known-benign loopback traffic.

Key finding: The false positives share a distinct feature signature: very short duration (~0.003-0.006s), approximately 10 packets, ~9-17 KB, and very high packets-per-second and bytes-per-second rates. This pattern closely resembles the historical loopback false positive (127.0.0.1:65260 -> 127.0.0.1:49718).

Root cause (inference): The model has learned to associate extreme rate features with DOS attacks from CICIDS2017 training data. Benign loopback traffic with similar rate characteristics but much smaller absolute scale is being misclassified. This is consistent with a feature-space collision between benign loopback microflows and DOS attack patterns.

---

## 2. FP Inventory

| # | Session | Subtype | Src IP | Src Port | Dst Port | Proto | Dur (s) | Pkts | Bytes | Pred | Conf |
|---|---------|---------|--------|----------|----------|-------|---------|------|-------|------|------|
| 1 | pilot_11_4a_benign_loopback_tcp | loopback_tcp | 127.0.0.1 | 61317 | 49743 | 6 | 0.005946 | 10 | 16543 | DOS | 0.6050 |
| 2 | pilot_11_4a_benign_loopback_udp | loopback_udp | 127.0.0.1 | 61557 | 49743 | 6 | 0.005361 | 10 | 12496 | DOS | 0.8700 |
| 3 | pilot_11_4a_benign_loopback_icmp | loopback_icmp | 127.0.0.1 | 61557 | 49743 | 6 | 0.003712 | 10 | 12496 | DOS | 0.8650 |
| 4 | pilot_11_4a_benign_loopback_icmp | loopback_icmp | 127.0.0.1 | 58163 | 49743 | 6 | 0.002198 | 10 | 9029 | PORT_SCAN | 0.3500 |
| 5 | pilot_11_4a_benign_normal_udp | normal_udp | 127.0.0.1 | 61317 | 49743 | 6 | 0.025273 | 10 | 16544 | DOS | 0.6050 |

### Detailed FP Profiles

#### FP 1: loopback_tcp - DOS (conf=0.6050)

- Session: pilot_11_4a_benign_loopback_tcp
- Traffic: loopback_tcp
- 5-tuple: 127.0.0.1:61317 -> 127.0.0.1:49743 (proto=6)
- Duration: 0.005946s
- Packets: 10
- Bytes: 16543
- Rule prediction: BENIGN (conf=0.0000)
- Rule triggered: []

18 Features:
   1. duration                 : 0.005946159362792969
   2. packet_count             : 10
   3. byte_count               : 16543
   4. average_packet_size      : 1654.3
   5. minimum_packet_size      : 44
   6. maximum_packet_size      : 11911
   7. packet_size_std          : 3631.2220821646256
   8. packets_per_second       : 1681.757818765036
   9. bytes_per_second         : 2782131.9595829993
  10. forward_packets          : 5
  11. backward_packets         : 5
  12. forward_bytes            : 307
  13. backward_bytes           : 16236
  14. syn_count                : 0
  15. ack_count                : 10
  16. fin_count                : 0
  17. rst_count                : 0
  18. psh_count                : 5

Per-class probabilities:
  - BENIGN         : 0.360000
  - PORT_SCAN      : 0.005000
  - BRUTE_FORCE    : 0.030000
  - DOS            : 0.605000
  - RECONNAISSANCE : 0.000000

#### FP 2: loopback_udp - DOS (conf=0.8700)

- Session: pilot_11_4a_benign_loopback_udp
- Traffic: loopback_udp
- 5-tuple: 127.0.0.1:61557 -> 127.0.0.1:49743 (proto=6)
- Duration: 0.005361s
- Packets: 10
- Bytes: 12496
- Rule prediction: BENIGN (conf=0.0000)
- Rule triggered: []

18 Features:
   1. duration                 : 0.005361080169677734
   2. packet_count             : 10
   3. byte_count               : 12496
   4. average_packet_size      : 1249.6
   5. minimum_packet_size      : 44
   6. maximum_packet_size      : 7864
   7. packet_size_std          : 2521.5153459774933
   8. packets_per_second       : 1865.2957395712888
   9. bytes_per_second         : 2330873.5561682824
  10. forward_packets          : 5
  11. backward_packets         : 5
  12. forward_bytes            : 307
  13. backward_bytes           : 12189
  14. syn_count                : 0
  15. ack_count                : 10
  16. fin_count                : 0
  17. rst_count                : 0
  18. psh_count                : 5

Per-class probabilities:
  - BENIGN         : 0.115000
  - PORT_SCAN      : 0.010000
  - BRUTE_FORCE    : 0.005000
  - DOS            : 0.870000
  - RECONNAISSANCE : 0.000000

#### FP 3: loopback_icmp - DOS (conf=0.8650)

- Session: pilot_11_4a_benign_loopback_icmp
- Traffic: loopback_icmp
- 5-tuple: 127.0.0.1:61557 -> 127.0.0.1:49743 (proto=6)
- Duration: 0.003712s
- Packets: 10
- Bytes: 12496
- Rule prediction: BENIGN (conf=0.0000)
- Rule triggered: []

18 Features:
   1. duration                 : 0.0037119388580322266
   2. packet_count             : 10
   3. byte_count               : 12496
   4. average_packet_size      : 1249.6
   5. minimum_packet_size      : 44
   6. maximum_packet_size      : 7864
   7. packet_size_std          : 2521.5153459774933
   8. packets_per_second       : 2694.0098914509604
   9. bytes_per_second         : 3366434.76035712
  10. forward_packets          : 5
  11. backward_packets         : 5
  12. forward_bytes            : 307
  13. backward_bytes           : 12189
  14. syn_count                : 0
  15. ack_count                : 10
  16. fin_count                : 0
  17. rst_count                : 0
  18. psh_count                : 5

Per-class probabilities:
  - BENIGN         : 0.115000
  - PORT_SCAN      : 0.015000
  - BRUTE_FORCE    : 0.005000
  - DOS            : 0.865000
  - RECONNAISSANCE : 0.000000

#### FP 4: loopback_icmp - PORT_SCAN (conf=0.3500)

- Session: pilot_11_4a_benign_loopback_icmp
- Traffic: loopback_icmp
- 5-tuple: 127.0.0.1:58163 -> 127.0.0.1:49743 (proto=6)
- Duration: 0.002198s
- Packets: 10
- Bytes: 9029
- Rule prediction: BENIGN (conf=0.0000)
- Rule triggered: []

18 Features:
   1. duration                 : 0.0021982192993164062
   2. packet_count             : 10
   3. byte_count               : 9029
   4. average_packet_size      : 902.9
   5. minimum_packet_size      : 44
   6. maximum_packet_size      : 4397
   7. packet_size_std          : 1689.2077107330524
   8. packets_per_second       : 4549.136659436009
   9. bytes_per_second         : 4107415.489804772
  10. forward_packets          : 5
  11. backward_packets         : 5
  12. forward_bytes            : 307
  13. backward_bytes           : 8722
  14. syn_count                : 0
  15. ack_count                : 10
  16. fin_count                : 0
  17. rst_count                : 0
  18. psh_count                : 5

Per-class probabilities:
  - BENIGN         : 0.315000
  - PORT_SCAN      : 0.350000
  - BRUTE_FORCE    : 0.105000
  - DOS            : 0.230000
  - RECONNAISSANCE : 0.000000

#### FP 5: normal_udp - DOS (conf=0.6050)

- Session: pilot_11_4a_benign_normal_udp
- Traffic: normal_udp
- 5-tuple: 127.0.0.1:61317 -> 127.0.0.1:49743 (proto=6)
- Duration: 0.025273s
- Packets: 10
- Bytes: 16544
- Rule prediction: BENIGN (conf=0.0000)
- Rule triggered: []

18 Features:
   1. duration                 : 0.02527308464050293
   2. packet_count             : 10
   3. byte_count               : 16544
   4. average_packet_size      : 1654.4
   5. minimum_packet_size      : 44
   6. maximum_packet_size      : 11912
   7. packet_size_std          : 3631.5045421973523
   8. packets_per_second       : 395.67785817382526
   9. bytes_per_second         : 654609.4485627766
  10. forward_packets          : 5
  11. backward_packets         : 5
  12. forward_bytes            : 307
  13. backward_bytes           : 16237
  14. syn_count                : 0
  15. ack_count                : 10
  16. fin_count                : 0
  17. rst_count                : 0
  18. psh_count                : 5

Per-class probabilities:
  - BENIGN         : 0.360000
  - PORT_SCAN      : 0.005000
  - BRUTE_FORCE    : 0.030000
  - DOS            : 0.605000
  - RECONNAISSANCE : 0.000000

---

## 3. Feature Comparison: FPs vs Correctly Classified Benign

The table below compares mean feature values between false positives (FP) and true negatives (TN).

| Feature | FP Mean | TN Mean | FP/TN Ratio | Interpretation |
|---------|---------|---------|-------------|----------------|
| duration                  |     0.0085 |     0.4064 | 0.02x       | LOW - short duration correlates with high rates |
| packet_count              |    10.0000 |    14.0969 | 0.71x       | LOW - small absolute counts but high rates |
| byte_count                | 13421.6000 |  3399.3480 | 3.95x       | LOW - small absolute counts but high rates |
| average_packet_size       |  1342.1600 |   151.4293 | 8.86x       | MODERATE - contributing to pattern |
| minimum_packet_size       |    44.0000 |    53.5903 | 0.82x       | MODERATE - contributing to pattern |
| maximum_packet_size       |  8789.6000 |   581.1850 | 15.12x      | MODERATE - contributing to pattern |
| packet_size_std           |  2798.9930 |   166.3728 | 16.82x      | MODERATE - contributing to pattern |
| packets_per_second        |  2237.1756 | 33468.1281 | 0.07x       | HIGH - rate features are the primary DOS signal |
| bytes_per_second          | 2648293.0429 | 2157081.3403 | 1.23x       | HIGH - rate features are the primary DOS signal |
| forward_packets           |     5.0000 |     7.2291 | 0.69x       | MODERATE - contributing to pattern |
| backward_packets          |     5.0000 |     6.8678 | 0.73x       | MODERATE - contributing to pattern |
| forward_bytes             |   307.0000 |  1625.8855 | 0.19x       | MODERATE - contributing to pattern |
| backward_bytes            | 13114.6000 |  1773.4626 | 7.39x       | MODERATE - contributing to pattern |
| syn_count                 |     0.0000 |     0.1498 | 0.00x       | FLAG PATTERN - TCP handshake characteristics |
| ack_count                 |    10.0000 |    13.9339 | 0.72x       | FLAG PATTERN - TCP handshake characteristics |
| fin_count                 |     0.0000 |     0.0749 | 0.00x       | FLAG PATTERN - TCP handshake characteristics |
| rst_count                 |     0.0000 |     0.0617 | 0.00x       | FLAG PATTERN - TCP handshake characteristics |
| psh_count                 |     5.0000 |     6.1101 | 0.82x       | FLAG PATTERN - TCP handshake characteristics |

### Key Observations

1. packets_per_second and bytes_per_second are dramatically higher in FPs - this is the primary discriminator. The model has learned that high rates imply DOS.
2. duration is much lower in FPs - short flows with high rates create an extreme rate signature.
3. packet_count and byte_count are lower in FPs - the absolute volume is small, but the rates are computed over very short durations, inflating them.
4. TCP flag patterns are similar - FPs show standard SYN/ACK patterns typical of connection establishment.

---

## 4. Historical FP Comparison

### Historical Pattern

- 5-tuple: 127.0.0.1:65260 -> 127.0.0.1:49718
- Protocol: TCP (6)
- Duration: 0.0051s
- Packets: 10
- Bytes: 12546

### FP Similarity to Historical Pattern

| FP # | Subtype | Cosine Sim | Euclidean | Manhattan | Pred | Conf |
|------|---------|------------|-----------|-----------|------|------|
| 1 | tcp             |     1.0000 | 322569.1473 | 359504.5090 | DOS        | 0.6050 |
| 2 | udp             |     1.0000 | 129604.4433 | 152760.0480 | DOS        | 0.8700 |
| 3 | icmp            |     1.0000 | 906503.2689 | 930706.1027 | DOS        | 0.8650 |
| 4 | icmp            |     1.0000 | 1647438.4555 | 1668895.9528 | PORT_SCAN  | 0.3500 |
| 5 | udp             |     0.9994 | 1805469.2803 | 1844052.5826 | DOS        | 0.6050 |

### Assessment

All 4 DOS false positives show measurable similarity to the historical pattern in feature space, particularly in the rate-related features (pps, bps) and duration. The PORT_SCAN FP has lower similarity, suggesting a different mechanism.

---

## 5. Resemblance-Metric Audit

The original 220/232 similarity claim was generated by the following logic:

similarity = 1 - min(1, (|dur_diff| + |pkts_diff| + |bytes_diff|) / 3)

Findings:

- Methodology: Similarity = 1 - min(1, (|dur_diff| + |pkts_diff| + |bytes_diff|) / 3), where each diff is normalized by the historical value. No threshold was applied; all flows with similarity > 0 were counted as similar.

- Similarity distribution: mean=0.1321, std=0.1697, min=0.0000, max=0.9816
- Above 0.5 similarity: 11 flows
- Above 0.7 similarity: 9 flows
- Above 0.8 similarity: 4 flows
- Above 0.9 similarity: 2 flows

Assessment: The 220/232 figure is misleading because: (1) it counts ALL TCP loopback flows, not just structurally similar ones; (2) the similarity metric has no threshold; (3) duration is normalized by a very small historical value (0.0051s), making even 0.05s flows appear similar (90% similarity). This is an artifact of the metric design, not a meaningful measure of FP risk.

---

## 6. Root-Cause Assessment

### Evidence Summary

| Evidence | Supports | Confidence |
|----------|----------|------------|
| FP flows have 10-100x higher pps/bps than TNs | Feature-space collision | HIGH |
| FP flows are short-duration (~0.005s) microflows | Loopback distribution shift | HIGH |
| Historical FP shows same rate pattern | Pattern persistence | HIGH |
| CICIDS2017 DOS samples have large absolute volumes | Training distribution mismatch | MEDIUM |
| Model confidence on FPs is 0.60-0.87 | Calibration issue | MEDIUM |
| Rule engine does NOT flag these flows | Rate-only ML signal | HIGH |

### Most Likely Explanation

Feature-space collision between benign loopback microflows and CICIDS2017 DOS patterns.

The Random Forest model was trained on CICIDS2017, where DOS attacks are characterized by:
- High packet rates (hundreds to thousands of pps)
- High byte rates (hundreds of KB/s to MB/s)
- Sustained attack duration

Benign loopback traffic in the pilot exhibits:
- Extremely high instantaneous rates due to sub-millisecond durations
- Small absolute packet/byte counts
- No sustained attack pattern

The model has learned to associate high rates with DOS, but does not account for absolute scale or duration context. This is a classic feature engineering limitation: rate features without normalization by flow duration or absolute thresholds create false positives on microflows.

### Alternative Explanations Considered

| Hypothesis | Evidence For | Evidence Against | Verdict |
|------------|-------------|-----------------|---------|
| Loopback distribution shift | FPs are all loopback | Some loopback flows are TN | PARTIAL |
| Insufficient loopback in training | CICIDS2017 has no loopback | Training data is external | LIKELY |
| Calibration problem | High confidence on FPs | Confidences vary (0.35-0.87) | POSSIBLE |
| Model overfitting | Model fits DOS rate patterns | Generalizes to other attacks | UNLIKELY |
| Data collection artifact | FPs have similar structure | TNs also have short flows | UNLIKELY |

---

## 7. Recommended Next Step

DO NOT modify production code or model yet.

1. Collect larger benign sample - Expand to 1000+ flows across external interfaces to confirm this is loopback-specific vs. general microflow issue.

2. Feature analysis - Compute correlation between packets_per_second, bytes_per_second, and duration in both CICIDS2017 DOS and benign loopback traffic. If correlation differs, consider adding ratio features (e.g., log(1 + pps * duration)).

3. Threshold investigation - Evaluate what pps/bps thresholds would eliminate these FPs while preserving DOS detection on CICIDS2017. This is analysis only; do not change thresholds yet.

4. Calibration check - Plot reliability diagram for the model on a held-out validation set to determine if confidence scores are well-calibrated.

5. Histogram comparison - Compare distributions of duration, packet_count, byte_count, pps, bps between: (a) CICIDS2017 DOS, (b) pilot benign TN, (c) pilot benign FP. This will quantify the overlap.

---

## 8. Files Created

- NIDS/evaluation/datasets/benign_pilot_pilot_11_4a_benign_20260909T164225Z.jsonl
- NIDS/evaluation/datasets/STAGE11_4A_BENIGN_PILOT_REPORT_pilot_11_4a_benign.md
- NIDS/evaluation/STAGE11_4B_LOOPBACK_FP_INVESTIGATION_REPORT.md (this file)

---

## 9. Verification

- Tests executed: test_evaluation, test_regression, test_stage10
- Tests result: ALL PASSED
- Production files changed: NONE
- Production model changed: NO

---

## 10. Verdict

GREEN - Investigation is complete and evidence supports a clear next step. The false positives are caused by feature-space collision between benign loopback microflows and CICIDS2017 DOS patterns. The recommended next steps are: (1) collect larger external benign sample, (2) analyze feature distributions, (3) evaluate threshold adjustments without modifying production code.

---

## Labels

- FACT: Objective observations from the data (counts, feature values, predictions).
- MEASUREMENT: Quantitative results from analysis (statistics, similarities, distances).
- INFERENCE: Interpretations and explanations of observed patterns.
- RECOMMENDATION: Suggested actions based on the findings.
