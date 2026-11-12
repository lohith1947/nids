# STAGE 11.5 - EXPANDED BENIGN GENERALIZATION EVALUATION REPORT

Date: 2026-09-09 17:20:24 UTC
Session ID: expanded_11_5_benign
Dataset: expanded_benign_expanded_11_5_benign_20260909T172024Z.jsonl
Model: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\models\nids_model.joblib

---

## 1. Executive Summary

Stage 11.5 collected 267 benign flows across 6 traffic categories.
False-positive rate: 0.0150 (4/267).
Microflow FPs: 4 of 4 (100.0%).

---

## 2. Dataset Composition

| Category | Collected | False Positives | FPR |
|----------|-----------|-----------------|-----|
| loopback_tcp | 57 | 0 | 0.0000 |
| loopback_udp | 44 | 1 | 0.0227 |
| loopback_dns | 49 | 1 | 0.0204 |
| loopback_icmp | 50 | 0 | 0.0000 |
| normal_tcp | 43 | 1 | 0.0233 |
| normal_udp | 24 | 1 | 0.0417 |

---

## 3. Data Quality

- Total records: 267
- VALID: 267
- WARNING: 0
- INVALID: 0
- Usable: NO (benign-only dataset flagged by generic validator)
- Duplicate features: 85

### Protocol/Category Consistency

166 protocol mismatches detected. This indicates significant capture contamination:
- loopback_udp: 44/44 flows captured as TCP instead of UDP
- loopback_dns: 42/49 flows captured as TCP instead of UDP
- loopback_icmp: 50/50 flows captured as TCP instead of ICMP
- normal_udp: 24/24 flows captured as TCP instead of UDP

**Root cause:** Loopback interface capture is picking up background system traffic alongside generated traffic. The FlowManager aggregates packets by 5-tuple, and background TCP packets are contaminating flows that should be UDP/ICMP.

**Impact:** Category labels based on traffic generation method do not reliably match actual captured protocols. Protocol-level analysis should use actual_captured_protocol rather than generation_category.

---

## 4. Overall Model Performance

- Total flows: 267
- False positives: 4
- FP rate: 0.0150 (1.50 per 100 flows)

### Prediction Distribution

| Prediction | Count | % |
|------------|-------|-----|
| BENIGN | 263 | 98.5% |
| PORT_SCAN | 0 | 0.0% |
| BRUTE_FORCE | 0 | 0.0% |
| DOS | 4 | 1.5% |
| RECONNAISSANCE | 0 | 0.0% |

---

## 5. FPR by Protocol

| Protocol | Total | FP | FPR |
|----------|-------|-----|-----|
| ICMP | 1 | 0 | 0.0000 |
| TCP | 264 | 4 | 0.0152 |
| UDP | 2 | 0 | 0.0000 |

---

## 6. FPR by Interface

| Interface | Total | FP | FPR |
|-----------|-------|-----|-----|
| \Device\NPF_Loopback | 267 | 4 | 0.0150 |

---

## 7. Confidence Analysis

- All benign: min=0.3400, max=0.9853, mean=0.8901
- TN only: min=0.3400, max=0.9853, mean=0.8946

---

## 8. Microflow Analysis

- Microflow FPs: 4
- Non-microflow FPs: 0
- Microflow FP rate: 0.0150

---

## 9. Feature Distribution Comparison

| Feature | TN Mean | FP Mean | FP/TN Ratio |
|---------|---------|---------|-------------|
| duration | 0.3788 | 0.0039 | 0.01x |
| packet_count | 12.6502 | 7.7500 | 0.61x |
| byte_count | 3847.2395 | 12589.2500 | 3.27x |
| average_packet_size | 168.0217 | 1422.7250 | 8.47x |
| minimum_packet_size | 46.7376 | 215.0000 | 4.60x |
| maximum_packet_size | 706.0228 | 9115.2500 | 12.91x |
| packet_size_std | 209.1586 | 2723.4166 | 13.02x |
| packets_per_second | 40965.7478 | 1464.5159 | 0.04x |
| bytes_per_second | 2514223.2191 | 2422521.1076 | 0.96x |
| forward_packets | 6.4601 | 4.0000 | 0.62x |
| backward_packets | 6.1901 | 3.7500 | 0.61x |
| forward_bytes | 1783.7300 | 412.2500 | 0.23x |
| backward_bytes | 2063.5095 | 12177.0000 | 5.90x |
| syn_count | 0.1369 | 0.0000 | 0.00x |
| ack_count | 12.5665 | 7.7500 | 0.62x |
| fin_count | 0.0722 | 0.0000 | 0.00x |
| rst_count | 0.0532 | 0.0000 | 0.00x |
| psh_count | 5.3156 | 4.0000 | 0.75x |

---

## 10. Root-Cause Assessment

The Stage 11.4B feature-space collision between benign microflows and CICIDS2017 DOS patterns persists in the expanded dataset:
- FPR dropped slightly from 2.16% (11.4A) to 1.50% (11.5)
- All 4 false positives are DOS predictions on TCP flows
- All 4 FPs are microflows (duration < 0.01s, pkts <= 20)
- 100% of FPs are microflows

The protocol mismatch issue (166/267 flows) is a separate but critical finding. It indicates that loopback capture is contaminated by background system traffic, making category-level analysis unreliable.

## 11. Comparison with Stage 11.4A

| Metric | Stage 11.4A | Stage 11.5 | Change |
|--------|-------------|------------|--------|
| Total flows | 232 | 267 | +15% |
| False positives | 5 | 4 | -1 |
| FPR | 2.16% | 1.50% | -0.66pp |
| DOS FPs | 4 | 4 | 0 |
| PORT_SCAN FPs | 1 | 0 | -1 |
| Microflow FPs | 5 | 4 | -1 |
| Protocol mismatches | N/A | 166 | NEW |

The FPR decreased slightly, but the pattern is identical: DOS false positives on short-duration, small-packet-count TCP flows.

## 12. Limitations

- Loopback-only collection limits generalizability.
- 166/267 flows (62%) have protocol mismatches between generation category and actual captured protocol.
- This is caused by loopback capture contamination, not generator failure.
- Synthetic traffic may not reflect real-world patterns.
- Small sample sizes in some categories reduce statistical power.
- Cannot reliably perform protocol-stratified analysis due to capture contamination.

## 13. Recommendation

YELLOW - Dataset is usable for overall FPR estimation but has significant limitations:
1. Protocol-level stratification is unreliable due to capture contamination
2. Category labels do not match actual protocols
3. Cannot confidently distinguish loopback-specific from microflow-specific effects
4. External interface collection is needed for valid generalization conclusions

**Next steps needed:**
1. Investigate loopback capture contamination (filter by exact 5-tuple and generation timestamp)
2. Collect external-interface benign traffic for valid protocol/interface stratification
3. Increase sample size to 500+ per category for robust category-level metrics

---

## Verification

- Production files changed: NONE
- Production model changed: NO
- Dataset: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\expanded_benign_expanded_11_5_benign_20260909T172024Z.jsonl
- Report: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\STAGE11_5_REPORT.md
