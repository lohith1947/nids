# STAGE 11.8 - CONTROLLED ATTACK VALIDATION REPORT

Date: 2026-09-10 13:19:50 UTC

---

## 1. Executive Summary

This report presents an observational evaluation of the existing NIDS against real controlled attack traffic.

- **Overall Accuracy:** 0.4007
- **Macro F1:** 0.4604
- **Macro Recall:** 0.4356
- **Total Flows:** 1520

**Verdict: RED** - Major evaluation integrity failure or extremely poor detection.

---

## 2. Objective

Evaluate whether the existing NIDS can detect real controlled attack traffic in an isolated lab environment.

---

## 3. Environment / Lab Target

- **Target:** loopback (127.0.0.1, 127.0.0.2-6)
- **Isolation:** localhost only, no external targets
- **Safety:** all traffic bounded and controlled

---

## 4. Dataset and Ground Truth

| Attack Class | Target | Generated | Attributed | Valid |
|--------------|--------|-----------|------------|-------|
| PORT_SCAN | localhost | 500 | 500 | 500 |
| BRUTE_FORCE | localhost | 500 | 500 | 500 |
| DOS | localhost | 20 | 20 | 20 |
| RECONNAISSANCE | localhost | 500 | 500 | 500 |

**Total:** 1520 flows

---

## 5. Attack Generation Method

- PORT_SCAN: TCP connections to ports 52000-52100, 5 attempts each
- BRUTE_FORCE: Repeated TCP connections to port 22
- DOS: UDP flood, 1000 packets per flow, 20 flows
- RECONNAISSANCE: TCP connections to 127.0.0.2-6 on port 55000

---

## 6. Attribution Method

Server-side DirectFlowTracker. All flows are client-to-server on dedicated ports.

---

## 7. Dataset Integrity

- Total flows: 1520
- Attributed: 1520
- Unattributed: 0
- Contaminated: 0
- Duplicates: 1285

---

## 8. Model Identity

- Model: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\models\nids_model.joblib
- Hash: 7bcc643154a1f44d
- Type: RandomForestClassifier
- Features: 18 numeric

---

## 9. Overall Metrics

| Metric | Value |
|--------|-------|
| total | 1520.0000 |
| accuracy | 0.4007 |
| macro_precision | 0.6000 |
| macro_recall | 0.4356 |
| macro_f1 | 0.4604 |
| weighted_precision | 0.6711 |
| weighted_recall | 0.4007 |
| weighted_f1 | 0.4415 |

---

## 10. Per-Class Metrics

| Class | Support | Precision | Recall | F1 |
|-------|---------|-----------|--------|----|
| BENIGN | 0.0 | 0.0000 | 0.0000 | 0.0000 |
| PORT_SCAN | 500.0 | 0.0000 | 0.0000 | 0.0000 |
| BRUTE_FORCE | 500.0 | 1.0000 | 1.0000 | 1.0000 |
| DOS | 20.0 | 1.0000 | 1.0000 | 1.0000 |
| RECONNAISSANCE | 500.0 | 1.0000 | 0.1780 | 0.3022 |

---

## 11. Confusion Matrix

Rows = ground truth, Columns = prediction

| GT \ Pred | BENIGN | PORT_SCAN | BRUTE_FORCE | DOS | RECONNAISSANCE |
|---|---|---|---|---|---|
| BENIGN | 0 | 0 | 0 | 0 | 0 |
| PORT_SCAN | 500 | 0 | 0 | 0 | 0 |
| BRUTE_FORCE | 0 | 0 | 500 | 0 | 0 |
| DOS | 0 | 0 | 0 | 20 | 0 |
| RECONNAISSANCE | 411 | 0 | 0 | 0 | 89 |

---

## 12. Rule vs ML vs Hybrid Analysis

- Rule-only detections: 609
- ML-only detections: 0
- Hybrid detections: 0
- Agreement: 911
- Disagreement: 609

---

## 13. Detection Latency

- Count: 1520
- Mean: 19.2689 seconds
- Median: 19.8182 seconds
- P95: 24.0248 seconds
- Max: 24.7351 seconds

---

## 14. Attack Profile Analysis

See per-session counts in dataset metadata.

---

## 15. Duplicate Analysis

- Total records: 1520
- Unique feature vectors: 235
- Duplicate count: 1285
- Duplicate percentage: 84.54%

---

## 16. False Negative Analysis

See per-flow CSV for detailed FNs.

---

## 17. Limitations

- Loopback-only collection.
- No real authentication responses for BRUTE_FORCE.
- Limited diversity in feature space.

---

## 18. Acceptance Criteria

- Overall macro F1 >= 0.85: FAIL (0.4604)
- DOS recall >= 0.90: 1.0000
- PORT_SCAN recall >= 0.85: 0.0000
- BRUTE_FORCE recall >= 0.80: 1.0000
- RECONNAISSANCE recall >= 0.60: 0.1780

---

## 19. Reproducibility

- Model hash: 7bcc643154a1f44d
- Collection script: collect_attack_11_8.py
- Evaluation script: evaluate_attack_11_8.py
- Dataset: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\attack_11_8_20260910T131949Z.jsonl

---

## 20. Production Safety

- No production files modified.
- No model retraining.
- No threshold tuning.

---

## 21. Final Verdict

Overall macro F1: 0.4604
Per-class recall: BENIGN=0.0000, PORT_SCAN=0.0000, BRUTE_FORCE=1.0000, DOS=1.0000, RECONNAISSANCE=0.1780
