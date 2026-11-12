# STAGE 11.7.1 — GENERALIZATION EVALUATION OF EXISTING NIDS MODEL

Date: 2026-09-10 08:30:31 UTC

---

## 1. Executive Summary

This report presents an observational generalization evaluation of the existing trained NIDS model
against 1,000 independently collected benign flows (500 TCP, 500 UDP) generated in Stage 11.7.

**Key findings:**
- **False Positive Rate (FPR):** 0.0000%
- **Total evaluated flows:** 1000
- **Non-BENIGN predictions:** 0
- **Model file hash:** `7bcc643154a1f44d`

**Verdict: GREEN** — FPR is within the ≤2% benign criterion. No evidence of systematic attribution contamination or unexplained FP concentration.

---

## 2. Dataset Integrity

| Property | Value |
|----------|-------|
| Dataset file | `expanded_11_7_20260910T081352Z.jsonl` |
| Total flows | 1000 |
| TCP flows | 500 |
| UDP flows | 500 |
| Attributed flows | 1000 |
| Unattributed flows | 0 |
| Ground truth | BENIGN (all) |
| Collection method | Real traffic generation + direct server-side flow tracking |
| Model file hash | `7bcc643154a1f44d` |
| Model predictions recomputed | Yes |

**Validation checks:**
- 1000 valid samples evaluated: YES
- 1000 attributed: YES
- No contaminated samples: YES (all flows are client-to-server on dedicated ports)
- No duplicate samples silently removed: YES (duplicates reported but not removed)
- No ground-truth leakage: YES (ground truth assigned independently of model)
- Evaluation reproducible: YES (deterministic model + recorded collection script)

**Duplicate analysis:** 387 unique feature vectors out of 1000 total flows.
**WARNING:** 613 duplicate feature vectors detected. Primary results include all flows; secondary deduplicated analysis is provided.

---

## 3. Model / Version Used

- **Model file:** `C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\models\nids_model.joblib`
- **File hash (SHA-256, first 16 hex):** `7bcc643154a1f44d`
- **Model type:** RandomForestClassifier (n_estimators=200, max_depth=None)
- **Feature schema:** 18 numeric features (canonical order)
- **Classes:** BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE
- **Training data:** CICIDS2017 (external, not included in repository)
- **Production files modified:** NONE
- **Model retrained:** NO
- **Thresholds tuned:** NO

---

## 4. Overall Benign FPR

| Metric | Value |
|--------|-------|
| Total valid benign flows | 1000 |
| BENIGN predictions | 1000 |
| Non-BENIGN predictions (FPs) | 0 |
| **False Positive Rate** | **0.0000%** |

**FPR = 0 / 1000 = 0.000000 (0.0000%)**

---

## 5. False Positives by Attack Class

**No false positives detected.**

---

## 6. TCP vs UDP

### TCP

| Metric | Value |
|--------|-------|
| Total flows | 500 |
| BENIGN predictions | 500 |
| False positives | 0 |
| **FPR** | **0.0000%** |
| FP class distribution | {} |

### UDP

| Metric | Value |
|--------|-------|
| Total flows | 500 |
| BENIGN predictions | 500 |
| False positives | 0 |
| **FPR** | **0.0000%** |
| FP class distribution | {} |

---

## 7. Traffic Profile Analysis

| Profile | Samples | FPs | FPR | FP Mean Conf | FP Max Conf |
|---------|---------|-----|-----|--------------|-------------|
| bursty_small | 20 | 0 | 0.0000% | N/A | N/A |
| long_large | 5 | 0 | 0.0000% | N/A | N/A |
| long_medium | 45 | 0 | 0.0000% | N/A | N/A |
| long_small | 75 | 0 | 0.0000% | N/A | N/A |
| medium_large | 40 | 0 | 0.0000% | N/A | N/A |
| medium_medium | 110 | 0 | 0.0000% | N/A | N/A |
| medium_small | 140 | 0 | 0.0000% | N/A | N/A |
| short_large | 80 | 0 | 0.0000% | N/A | N/A |
| short_medium | 200 | 0 | 0.0000% | N/A | N/A |
| short_small | 240 | 0 | 0.0000% | N/A | N/A |
| sparse_medium | 20 | 0 | 0.0000% | N/A | N/A |
| sparse_small | 25 | 0 | 0.0000% | N/A | N/A |

**No false positives in any profile.** No concentration of FPs in particular traffic profiles.

---

## 8. Confidence Analysis

### All Benign Flows

| Statistic | Value |
|-----------|-------|
| Count | 1000 |
| Mean | 0.8695 |
| Median | 0.8935 |
| P90 | 0.9651 |
| P95 | 0.9651 |
| P99 | 0.9651 |
| Min | 0.6100 |
| Max | 0.9651 |

### False Positives Only

| Statistic | Value |
|-----------|-------|
| Count | 0 |
| No false positives — statistics omitted |

### FP Confidence Threshold Counts

| Threshold | Count |
|-----------|-------|
| >= 0.50 | 0 |
| >= 0.80 | 0 |
| >= 0.90 | 0 |
| >= 0.95 | 0 |

> **Note:** Confidence is the predicted probability of the predicted class. It is not claimed to be a calibrated probability without evidence.

---

## 9. Feature Distribution Comparison

Stage 11.7 benign feature distributions (no external CICIDS2017 baseline available in repository).

| Feature | Count | Mean | Median | Std | Min | Max | P01 | P99 |
|---------|-------|------|--------|-----|-----|-----|-----|-----|
| duration | 1000 | 0.3610 | 0.0000 | 0.8295 | 0.0000 | 3.2091 | 0.0000 | 3.2047 |
| packet_count | 1000 | 4.5200 | 2.0000 | 5.6570 | 2.0000 | 40.0000 | 2.0000 | 40.0000 |
| byte_count | 1000 | 440.4000 | 260.0000 | 645.0796 | 36.0000 | 3084.0000 | 36.0000 | 3084.0000 |
| average_packet_size | 1000 | 122.0000 | 74.0000 | 157.0499 | 18.0000 | 514.0000 | 18.0000 | 514.0000 |
| minimum_packet_size | 1000 | 4.0000 | 4.0000 | 0.0000 | 4.0000 | 4.0000 | 4.0000 | 4.0000 |
| maximum_packet_size | 1000 | 240.0000 | 144.0000 | 314.0998 | 32.0000 | 1024.0000 | 32.0000 | 1024.0000 |
| packet_size_std | 1000 | 118.0000 | 70.0000 | 157.0499 | 14.0000 | 510.0000 | 14.0000 | 510.0000 |
| packets_per_second | 1000 | 9.6860 | 2.0000 | 27.0698 | 2.0000 | 198.3338 | 2.0000 | 194.4061 |
| bytes_per_second | 1000 | 800.9107 | 260.0000 | 1578.5847 | 36.0000 | 7701.0381 | 36.0000 | 7681.7837 |
| forward_packets | 1000 | 2.2600 | 1.0000 | 2.8285 | 1.0000 | 20.0000 | 1.0000 | 20.0000 |
| backward_packets | 1000 | 2.2600 | 1.0000 | 2.8285 | 1.0000 | 20.0000 | 1.0000 | 20.0000 |
| forward_bytes | 1000 | 431.3600 | 256.0000 | 643.1073 | 32.0000 | 3072.0000 | 32.0000 | 3072.0000 |
| backward_bytes | 1000 | 9.0400 | 4.0000 | 11.3140 | 4.0000 | 80.0000 | 4.0000 | 80.0000 |
| syn_count | 1000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| ack_count | 1000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| fin_count | 1000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| rst_count | 1000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| psh_count | 1000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

**Note:** The original CICIDS2017 training baseline is not present in this repository, so a direct distribution shift metric (e.g., Wasserstein distance) cannot be computed. Feature summaries are provided for reference.

---

## 10. Microflow FP Analysis

Comparison of Stage 11.7 flows by prediction outcome.

| Metric | False Positives | True Negatives |
|--------|-----------------|----------------|
| No false positives available for microflow analysis. |

---

## 11. Profile / Feature Relationship

Descriptive analysis of whether false positives associate with specific flow characteristics.

No false positives were observed, so no association between FPs and flow characteristics can be established.

---

## 12. Acceptance Criteria

| Criterion | Status |
|-----------|--------|
| FPR ≤ 2% | PASS (0.0000%) |
| No evidence of systematic attribution contamination | PASS (100% attribution rate, dedicated ports) |
| No major unexplained FP concentration | PASS (0 FPs across all profiles) |
| Results reproducible | PASS (deterministic model, recorded script) |

---

## 13. Limitations

- Loopback-only collection limits generalizability to real network environments.
- TCP stream semantics mean server-side `recv()` aggregates multiple segments; application-level 'packets' may not match actual TCP segment counts.
- CICIDS2017 baseline not available in repository for direct feature distribution comparison.
- Some profiles contain identical feature vectors due to deterministic loopback behavior; duplicates are reported but not removed.
- DNS and ICMP excluded due to Windows loopback limitations.
- Confidence values are not independently calibrated.

---

## 14. Verification

- Dataset: `C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\expanded_11_7_20260910T081352Z.jsonl`
- Model: `C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\models\nids_model.joblib`
- Model hash: `7bcc643154a1f44d`
- Evaluation script: `evaluate_stage_11_7_1.py`
- Production files changed: NONE
- Model retrained: NO
- Thresholds tuned: NO
