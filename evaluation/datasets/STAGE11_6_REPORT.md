# STAGE 11.6 - CONTROLLED BENIGN TRAFFIC ATTRIBUTION & COLLECTION REPORT

Date: 2026-09-09 18:27:07 UTC
Session ID: controlled_11_6_benign
Dataset: controlled_controlled_11_6_benign_20260909T182707Z.jsonl
Model: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\models\nids_model.joblib

---

## 1. Executive Summary

Stage 11.6 implements controlled traffic attribution using dedicated destination ports per category.
This addresses the Stage 11.5 contamination issue where 62% of flows had protocol mismatches.

---

## 2. Stage 11.5 Contamination Root Cause

In Stage 11.5, all traffic categories shared the loopback interface without unique identifiers.
Background system traffic contaminated generated flows, causing protocol mismatches:
- loopback_udp: 44/44 flows captured as TCP
- loopback_dns: 42/49 flows captured as TCP
- loopback_icmp: 50/50 flows captured as TCP
- normal_udp: 24/24 flows captured as TCP

Root cause: No separation between generated traffic and background loopback traffic.

---

## 3. Existing Collector Audit

collect_pilot_11_4a.py and collect_expanded_11_5.py:
- Use single sniff() on loopback interface
- No packet filtering by 5-tuple
- No timestamp correlation between generation and capture
- No protocol verification against expected protocol
- All remaining flows in FlowManager are returned as evidence

Result: Background traffic is indistinguishable from generated traffic.

---

## 4. Attribution Design

Each traffic category uses a dedicated destination port/IP:
- controlled_tcp: dedicated TCP port (50000+range)
- controlled_udp: dedicated UDP port (50100+range)
- controlled_dns: dedicated DNS port (50200+range)
- controlled_icmp: dedicated IP address (127.0.0.2)

Attribution statuses:
- ATTRIBUTED: exact 5-tuple and protocol match within time window
- CONTAMINATED: 5-tuple matches but protocol differs
- AMBIGUOUS: protocol matches but endpoints differ
- UNATTRIBUTED: no match found

---

## 5. Controlled Pilot Method

- Target: ~20 flows per category
- Each flow uses dedicated destination endpoint
- Generation events tracked with exact 5-tuple and timestamp
- Captured flows matched to generation events by 5-tuple + time window
- Only ATTRIBUTED flows included in analysis

---

## 6. Attribution Results

| Status | Count | Description |
|--------|-------|-------------|
| ATTRIBUTED | 39 | Exact 5-tuple + protocol + time match |
| CONTAMINATED | 0 | 5-tuple matches but protocol differs |
| AMBIGUOUS | 77 | Protocol matches but endpoints differ |
| UNATTRIBUTED | 346 | No matching generation event |

**Attribution rate:** 8.4%
**Total generated events:** 462
**Attributed flows:** 39

---

## 7. Protocol Validation

- Protocol mismatches in attributed flows: 0
- Total attributed flows: 39
- Mismatch rate: 0.00%

**PASS:** All attributed flows have correct protocol.

---

## 8. Data Quality

- Total records: 39
- VALID: 39
- WARNING: 0
- INVALID: 0
- Usable: NO
- Duplicate features: 0

---

## 9. Preliminary Model Observations

- Total attributed flows: 39
- False positives: 0
- FP rate: 0.0000 (0.00 per 100 flows)

### Prediction Distribution

| Prediction | Count | % |
|------------|-------|-----|
| BENIGN | 39 | 100.0% |
| PORT_SCAN | 0 | 0.0% |
| BRUTE_FORCE | 0 | 0.0% |
| DOS | 0 | 0.0% |
| RECONNAISSANCE | 0 | 0.0% |

**Note:** This is a small pilot (n=~20 per category). Do not draw broad FPR conclusions.

---

## 10. Remaining Limitations

- Loopback-only collection still limits generalizability.
- Small sample size (20 per category) is for attribution validation, not statistical power.
- ICMP uses dedicated IP (127.0.0.2) which may not be available on all systems.
- Background traffic may still match dedicated ports in some environments.

---

## 11. Recommendation for Stage 11.7


RED - Attribution methodology is not reliable enough for evaluation.
Do not proceed to larger collection until attribution is fixed.

---

## Verification

- Production files changed: NONE
- Production model changed: NO
- Dataset: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\controlled_controlled_11_6_benign_20260909T182707Z.jsonl
- Report: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\STAGE11_6_REPORT.md
- Attribution log: C:\Users\SRIRAM NAIDU\OneDrive\文档\Desktop\AI agent\NIDS\evaluation\datasets\controlled_controlled_11_6_benign_20260909T182707Z_attribution_log.json
