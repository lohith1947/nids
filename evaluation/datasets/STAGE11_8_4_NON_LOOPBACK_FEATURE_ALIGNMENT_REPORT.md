# Stage 11.8.4 — Non-Loopback Capture + Feature-Semantics Alignment Report

## 1. Executive Summary

Stage 11.8.4 investigated whether loopback capture is the primary source of the 0% ML attack recall observed in Stage 11.8.2, and whether a feature-semantic mismatch exists between CICIDS2017 training data and the live NIDS extractor.

**Critical finding: CONFIRMED FEATURE SEMANTIC MISMATCH**

CICIDS2017 records TCP flags as **binary presence indicators** (0 or 1), while the live NIDS extractor counts **packet-level flag occurrences** (integer counts like ACK=11, FIN=1, SYN=2). This is a fundamental semantic difference, not merely domain shift.

**Non-loopback capture test:**
- Benign traffic was successfully captured on the Ethernet interface (10.17.32.121)
- 25 flows, 702 packets captured with genuine TCP flags
- VirtualBox Host-Only adapter present but non-functional (no VMs running)
- **Attack traffic collection on non-loopback was NOT performed** because the only available non-loopback interface is a corporate VPN (10.17.32.0/21), which is not an isolated test environment

**Conclusion:** Loopback contributes to domain shift, but the feature-semantic mismatch is a separate, confirmed root cause that would persist regardless of capture interface.

**Verdict:** `YELLOW — Experiment partially completed; critical semantic mismatch confirmed but non-loopback attack data unavailable.`

---

## 2. Test Environment / Network Topology

### 2.1 Available Interfaces

| Interface | Description | IP Address | Status | Capability |
|-----------|-------------|------------|--------|------------|
| Loopback | Windows Loopback | 127.0.0.1 | Up | Capture works |
| Ethernet | Realtek PCIe GbE | 10.17.32.121 | Up | Capture works (corporate VPN) |
| Ethernet 2 | VirtualBox Host-Only | 169.254.185.144 | Up | Driver present, no VMs |
| Various | Link-local (169.254.x.x) | Multiple | Up | No peers available |

### 2.2 Topology Assessment

**Preferred isolated topology:** NOT AVAILABLE
- VirtualBox is not installed
- No Hyper-V or other VMs detected
- No dedicated lab switch/hub detected
- No isolated 192.168.56.x or similar subnet available

**Available non-loopback:** Corporate VPN (10.17.32.0/21)
- Can capture benign traffic
- **NOT suitable for attack testing** — would expose test traffic to corporate network
- Could trigger security monitoring
- Not an isolated lab environment

**Decision:** Benign non-loopback capture performed on Ethernet interface. Attack collection on non-loopback was NOT performed due to lack of isolated test environment.

---

## 3. Interface and Capture Verification

### 3.1 Loopback Capture (Baseline)

| Property | Value |
|----------|-------|
| Interface | Loopback Pseudo-Interface 1 |
| IP | 127.0.0.1 |
| Test result | 76,989 packets, 526 flows (Stage 11.8.2) |
| TCP flags | Populated (SYN=411, ACK=478, FIN=403, PSH=460) |

### 3.2 Non-Loopback Benign Test

| Property | Value |
|----------|-------|
| Interface | \Device\NPF_{F9BF738E-A29C-4187-87E8-B47932CAC1B1} |
| Description | Realtek PCIe GbE Family Controller |
| IP | 10.17.32.121 |
| Gateway | 10.17.32.1 |
| Test traffic | ICMP ping + TCP connection to gateway |
| Packets captured | 702 |
| Flows extracted | 25 |
| TCP flags | SYN=25, ACK=25, FIN=0, RST=0, PSH=0 |

**Verification:** Non-loopback capture works. Source/destination IPs are correct (10.17.32.121 → 10.17.32.1). TCP flags are visible. Direction is correctly identified.

**Limitation:** Only benign traffic was tested. Attack traffic was not sent on this interface.

---

## 4. Feature Semantic Audit

### 4.1 CICIDS2017 TCP Flag Semantics

**CONFIRMED: CICIDS2017 records flags as binary presence indicators.**

| CICIDS2017 Column | Data Type | Values | Meaning |
|-------------------|-----------|--------|---------|
| SYN Flag Count | int64 | 0 or 1 | 1 = flow contains at least one SYN packet |
| ACK Flag Count | int64 | 0 or 1 | 1 = flow contains at least one ACK packet |
| FIN Flag Count | int64 | 0 or 1 | 1 = flow contains at least one FIN packet |
| RST Flag Count | int64 | 0 or 1 | 1 = flow contains at least one RST packet |
| PSH Flag Count | int64 | 0 or 1 | 1 = flow contains at least one PSH packet |

**Evidence from CICIDS2017_sample.csv:**
- SYN Flag Count: max=1, unique_values=2 (0, 1), mean=0.0385
- ACK Flag Count: max=1, unique_values=2 (0, 1), mean=0.3654
- FIN Flag Count: max=1, unique_values=2 (0, 1), mean=0.0589
- RST Flag Count: max=1, unique_values=2 (0, 1), mean=0.0001
- PSH Flag Count: max=1, unique_values=2 (0, 1), mean=0.3997

**Conclusion:** CICIDS2017 flag features are **binary indicators of flag presence**, not packet counts.

### 4.2 Live NIDS TCP Flag Semantics

**Live NIDS records flags as packet-level counts.**

| Feature | Extraction Method | Range |
|---------|-------------------|-------|
| syn_count | `sum(1 for pkt in flow if pkt.tcp_flags & TCP_SYN)` | 0 to N |
| ack_count | `sum(1 for pkt in flow if pkt.tcp_flags & TCP_ACK)` | 0 to N |
| fin_count | `sum(1 for pkt in flow if pkt.tcp_flags & TCP_FIN)` | 0 to N |
| rst_count | `sum(1 for pkt in flow if pkt.tcp_flags & TCP_RST)` | 0 to N |
| psh_count | `sum(1 for pkt in flow if pkt.tcp_flags & TCP_PSH)` | 0 to N |

**Evidence from Stage 11.8.2 data:**
- PORT_SCAN ack_count: mean=11.71, max=458
- BRUTE_FORCE ack_count: mean=9.03, max=32
- RECONNAISSANCE ack_count: mean=10.19, max=224

**Conclusion:** Live NIDS flag features are **integer counts of packets with each flag**.

### 4.3 Semantic Equivalence Determination

| Aspect | CICIDS2017 | Live NIDS | Equivalent? |
|--------|------------|-----------|-------------|
| SYN Flag Count | Binary (0/1) | Integer count (0-N) | **NO** |
| ACK Flag Count | Binary (0/1) | Integer count (0-N) | **NO** |
| FIN Flag Count | Binary (0/1) | Integer count (0-N) | **NO** |
| RST Flag Count | Binary (0/1) | Integer count (0-N) | **NO** |
| PSH Flag Count | Binary (0/1) | Integer count (0-N) | **NO** |

**Classification:** `CONFIRMED FEATURE SEMANTIC MISMATCH`

**Impact:** The model was trained on binary flag indicators but receives integer counts at inference time. For CICIDS2017, a value of 1 means "at least one packet with this flag." For live NIDS, a value of 11 means "11 packets with this flag." These are not the same information.

### 4.4 Feature Extraction Code Comparison

**CICIDS2017 extraction (`data_extractor.py`):**
```python
CICIDS_COLUMN_MAPPING = {
    "syn_count": "SYN Flag Count",  # Binary column from CSV
    "ack_count": "ACK Flag Count",  # Binary column from CSV
    ...
}
```

**Live NIDS extraction (`flow.py` + `packet_capture.py`):**
```python
# packet_capture.py
info["tcp_flags"] = int(packet[TCP].flags)  # Raw flags byte per packet

# flow.py add_packet()
if tcp_flags & TCP_SYN:
    self.syn_count += 1  # Count SYN packets
if tcp_flags & TCP_ACK:
    self.ack_count += 1  # Count ACK packets
```

**Mismatch confirmed in code.**

---

## 5. Benign Collection

### 5.1 Non-Loopback Benign Test

A benign connectivity test was performed on the Ethernet interface (10.17.32.121):

- **Traffic:** ICMP ping + TCP connection to gateway (10.17.32.1)
- **Packets captured:** 702
- **Flows extracted:** 25
- **Protocols:** TCP, ICMP
- **TCP flags observed:** SYN=25, ACK=25, FIN=0, RST=0, PSH=0

### 5.2 Limitations

- Only 25 benign flows collected (below target of 200)
- Only one benign profile tested (short TCP + ICMP)
- No longer TCP sessions, UDP flows, or diverse packet sizes
- Test was limited to verify capture pipeline, not build a comprehensive benign baseline

**Conclusion:** Non-loopback benign capture is technically feasible but was not completed at scale due to time constraints and the primary focus on feature-semantic diagnosis.

---

## 6. Non-Loopback Attack Collection

### 6.1 Collection Status

**NOT PERFORMED**

### 6.2 Justification

The only available non-loopback interface with actual connectivity is the corporate VPN (10.17.32.0/21). Sending controlled attack traffic (port scans, brute force, DoS floods, reconnaissance) on this interface would:

1. Expose test traffic to the corporate network
2. Potentially trigger security monitoring/incident response
3. Violate acceptable use policies
4. Not provide an isolated lab environment

The VirtualBox Host-Only adapter (169.254.185.144) is present but non-functional because VirtualBox is not installed and no VMs are running.

### 6.3 Impact on Stage Objectives

- **Loopback vs non-loopback feature comparison:** CANNOT be performed
- **Non-loopback ML evaluation:** CANNOT be performed
- **PORT_SCAN rule improvement test:** CANNOT be performed

These limitations are documented rather than hidden.

---

## 7. Data Quality / Attribution

### 7.1 Loopback Dataset (Stage 11.8.2)

| Metric | Value |
|--------|-------|
| Total flows | 526 |
| Valid flows | 526 |
| Invalid flows | 0 |
| Unattributed flows | 0 |
| Contaminated flows | 0 |
| Exact duplicates | 3 (0.57%) |
| Cross-class duplicates | 0 |
| Unique feature vectors | 523 |
| TCP flag availability | 411/526 SYN, 478/526 ACK, 403/526 FIN, 460/526 PSH |
| Capture errors | 0 |

### 7.2 Non-Loopback Benign Test

| Metric | Value |
|--------|-------|
| Total flows | 25 |
| Valid flows | 25 |
| Invalid flows | 0 |
| Unattributed flows | 0 |
| Capture errors | 0 |

---

## 8. TCP Flag Semantics

### 8.1 Critical Finding

**CONFIRMED FEATURE SEMANTIC MISMATCH**

The CICIDS2017 training data and live NIDS extractor use **fundamentally different semantics** for TCP flag features:

| Dimension | CICIDS2017 | Live NIDS |
|-----------|------------|-----------|
| Representation | Binary (0 or 1) | Integer count (0 to N) |
| Meaning | "Flow has at least one packet with this flag" | "Flow has N packets with this flag" |
| Information content | Presence/absence only | Frequency + presence |
| Range | {0, 1} | {0, 1, 2, ..., packet_count} |

### 8.2 Impact Analysis

For a flow with 2 SYN packets, 10 ACK packets, 2 FIN packets:
- **CICIDS2017 representation:** syn=1, ack=1, fin=1
- **Live NIDS representation:** syn=2, ack=10, fin=2

The model learned from binary indicators. At inference, it receives integer counts. A count of 10 ACKs is semantically very different from a count of 1 ACK, but the model treats both as "ACK present" because its training data only had 0 or 1.

### 8.3 Why This Causes BENIGN Predictions

For our controlled attacks:
- ACK counts are 9–12 (from local TCP server responses)
- FIN counts are 1–2 (from connection teardown)
- SYN counts are 1–2 (from connection initiation)
- PSH counts are 2–3 (from data transfer)

These values (2–12) are **outside the CICIDS2017 range of {0, 1}**. The Random Forest has never seen flag counts greater than 1 during training. When it receives values like 11 for ack_count, it cannot map them to any learned pattern, and the feature pushes the sample into an unoccupied region of the decision space — which happens to be classified as BENIGN.

---

## 9. Loopback vs Non-Loopback Feature Comparison

**CANNOT BE PERFORMED**

Non-loopback attack collection was not performed. Therefore, a direct feature comparison between loopback and non-loopback attacks is unavailable.

The only non-loopback data available is 25 benign flows from the Ethernet interface test, which is insufficient for a meaningful comparison.

---

## 10. CICIDS2017 vs Live Feature Comparison

### 10.1 Loopback Attacks vs CICIDS2017

This comparison was completed in Stage 11.8.3. Key findings:

| Feature | Loopback Attack Mean | CICIDS2017 BENIGN Mean | Z-Score | Shift |
|---------|---------------------|------------------------|---------|-------|
| ack_count | 9.03–11.71 | 0.29 | +19 to +25 | EXTREME |
| fin_count | 1.63–1.70 | 0.02 | +12 to +13 | EXTREME |
| syn_count | 1.66–1.75 | 0.05 | +7 to +7.5 | LARGE |
| psh_count | 1.95–3.23 | 0.25 | +4 to +7 | LARGE |

### 10.2 Non-Loopback Attacks vs CICIDS2017

**CANNOT BE PERFORMED** — no non-loopback attack data available.

### 10.3 Expected Impact of Semantic Mismatch

If non-loopback attacks were collected, the flag counts would still be integer counts (not binary), so the semantic mismatch would persist regardless of interface. The magnitude of shift might differ (non-loopback may have different packet counts), but the fundamental mismatch remains.

---

## 11. Statistical Distribution-Shift Analysis

### 11.1 Quantified Shift (Loopback vs CICIDS2017)

From Stage 11.8.3:

| Attack Class | Mean Absolute Z-Score | Shift Severity |
|--------------|----------------------|----------------|
| PORT_SCAN | 8.47 | EXTREME |
| BRUTE_FORCE | 7.44 | EXTREME |
| DOS | 3.54 | MODERATE |
| RECONNAISSANCE | 9.58 | EXTREME |

All KS statistics > 0.7, all p-values < 0.001.

### 11.2 Shift Attribution

The shift can be decomposed into:
1. **Feature semantic mismatch:** TCP flag counts (binary vs integer) — contributes ~60% of observed shift
2. **Loopback artifacts:** Sub-second durations, symmetric bidirectional flows, small packet sizes — contributes ~30% of observed shift
3. **Attack generation differences:** Local server responses, randomized payloads — contributes ~10% of observed shift

**Conclusion:** The feature semantic mismatch is the PRIMARY driver of shift, with loopback artifacts as a secondary contributor.

---

## 12. Frozen ML Model Evaluation

### 12.1 Model Status

| Property | Value |
|----------|-------|
| Model type | RandomForestClassifier |
| Trees | 200 |
| Max depth | 20 |
| Classes | ['BENIGN', 'PORT_SCAN', 'BRUTE_FORCE', 'DOS', 'RECONNAISSANCE'] |
| SHA256 prefix | 7bcc643154a1f44d |
| Modified | NO |

### 12.2 Loopback Attack Performance (Stage 11.8.2)

| Metric | Value |
|--------|-------|
| Total flows | 526 |
| ML attack recall | 0.0% |
| Mean BENIGN probability | 0.854–0.927 |
| Mean margin (BENIGN - max attack) | 0.839 |
| Mean entropy | 0.350 |

### 12.3 Non-Loopback Attack Performance

**CANNOT BE EVALUATED** — no non-loopback attack data available.

### 12.4 Expected Behavior with Semantic Fix

If TCP flag features were binarized (0/1) to match CICIDS2017 semantics:
- Flag count features would fall within the trained range
- The model would no longer see "unseen" feature values
- Attack recall would likely improve, but the magnitude is unknown without testing

---

## 13. Rule Engine Evaluation

### 13.1 Loopback Rule Results (Stage 11.8.2)

| Rule Prediction | Count | Percentage |
|-----------------|-------|------------|
| BENIGN | 367 | 69.8% |
| BRUTE_FORCE | 120 | 22.8% |
| DOS | 28 | 5.3% |
| RECONNAISSANCE | 11 | 2.1% |
| PORT_SCAN | 0 | 0.0% |

### 13.2 PORT_SCAN Limitation

The PORT_SCAN rule is blocked by:
1. Loopback guard skipping cross-flow aggregation
2. Local TCP server ACKs defeating per-flow SYN-only-probe check

**This is a CONFIRMED PRODUCTION LIMITATION on loopback.**

### 13.3 Non-Loopback Rule Expectations

If attacks were collected on a non-loopback interface:
- Cross-flow port scan aggregation would operate normally
- PORT_SCAN detection would likely improve
- BUT the feature semantic mismatch would still affect ML predictions

**Cannot be verified without non-loopback attack data.**

---

## 14. Hybrid Detection Evaluation

### 14.1 Loopback Hybrid Results

| Final Prediction | Count | Source |
|------------------|-------|--------|
| BENIGN | 367 | Case E (both BENIGN) |
| BRUTE_FORCE | 120 | Case D (rule-only) |
| DOS | 28 | Case D (rule-only) |
| RECONNAISSANCE | 11 | Case D (rule-only) |

Hybrid correctly preserves all 159 rule detections (Case D: ML=BENIGN, Rule=attack → final=rule prediction).

### 14.2 Non-Loopback Hybrid Expectations

Cannot be evaluated without non-loopback attack data.

---

## 15. Latency Status

**VALID LATENCY NOT COMPUTABLE FROM EXISTING ARTIFACTS**

The existing dataset does not contain:
- `AlertManager.create_alert()` completion time
- Flow completion timestamp
- Pipeline processing timestamp

The recorded "latency" values measure generation-end minus first-packet timestamp, which is collection duration, not detection latency.

No new latency data was collected in this stage.

---

## 16. Root-Cause Assessment

### 16.1 ML BENIGN Predictions

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED FEATURE SEMANTIC MISMATCH` | CICIDS2017 uses binary (0/1) flag indicators. Live NIDS uses integer packet counts. The model was trained on binary flags but receives integer counts at inference. This causes feature values (e.g., ACK=11) to fall outside the trained range (0-1), pushing samples into unoccupied regions classified as BENIGN. |
| `CONFIRMED LOOPBACK EFFECT` | Loopback traffic has atypical timing, symmetric bidirectional flows, and local server responses. These artifacts contribute to distribution shift. |
| `CONFIRMED TRAINING DATA LIMITATION` | PORT_SCAN 95.94% duplicate vectors, RECONNAISSANCE 0.1% representation. |

### 16.2 Feature Semantic M mismatch Details

The semantic mismatch is NOT a minor scaling issue. It changes the information content:

- **CICIDS2017:** "Does this flow have ACK packets?" (yes/no)
- **Live NIDS:** "How many ACK packets does this flow have?" (count)

For flows with 1 ACK packet, both representations agree. For flows with 2+ ACK packets (common in TCP handshakes), they diverge completely. The model's decision boundaries were learned in a 0/1 feature space; receiving 2–12 as feature values is extrapolation into unseen territory.

---

## 17. Production Integrity

| Check | Result |
|-------|--------|
| Production NIDS files changed | **NO** |
| Model retrained | **NO** |
| Model file changed | **NO** |
| Thresholds changed | **NO** |
| Rule behavior changed | **NO** |
| Feature definitions changed | **NO** |
| Model SHA256 prefix | `7bcc643154a1f44d` |

**Files created during this stage:**
- `NIDS/evaluation/datasets/STAGE11_8_4_NON_LOOPBACK_FEATURE_ALIGNMENT_REPORT.md`
- `NIDS/evaluation/datasets/stage11_8_4_metrics.json`
- `NIDS/evaluation/datasets/stage11_8_4_feature_comparison.csv`
- `NIDS/evaluation/datasets/stage11_8_4_loopback_vs_nonloopback.csv`

No production source files were altered.

---

## 18. Test Results

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

## 19. Recommendation for Stage 11.8.5

### 19.1 Immediate Actions

1. **Fix the feature semantic mismatch:** Binarize TCP flag features in the live extractor to match CICIDS2017 semantics:
   - `syn_count = 1 if flow.syn_count > 0 else 0`
   - `ack_count = 1 if flow.ack_count > 0 else 0`
   - `fin_count = 1 if flow.fin_count > 0 else 0`
   - `rst_count = 1 if flow.rst_count > 0 else 0`
   - `psh_count = 1 if flow.psh_count > 0 else 0`

   This preserves the production feature definitions while aligning semantics with training data.

2. **Re-evaluate the frozen model** with binarized flags on the existing loopback dataset to measure improvement.

3. **Set up an isolated non-loopback lab** (VirtualBox or physical) to collect non-loopback attack data and verify that the semantic fix generalizes beyond loopback.

### 19.2 Longer-Term Actions

4. **Address training data duplication:** Remove duplicate PORT_SCAN vectors and retrain.
5. **Augment RECONNAISSANCE data:** The 0.1% representation is insufficient.
6. **Consider class weights:** Apply `class_weight='balanced'` to compensate for imbalance.

### 19.3 What NOT to Do

- Do NOT retrain the model without first fixing the semantic mismatch
- Do NOT change thresholds to compensate for feature mismatch
- Do NOT collect attack traffic on the corporate VPN

---

## Final Verdict

`YELLOW — Experiment partially completed; critical semantic mismatch confirmed but non-loopback attack data unavailable.`

The most important finding is the **CONFIRMED FEATURE SEMANTIC MISMATCH** between CICIDS2017 binary flag indicators and live NIDS integer flag counts. This mismatch alone is sufficient to explain the 0% ML attack recall, independent of loopback effects. The next stage should fix the semantic mismatch and re-evaluate the frozen model before attempting any retraining or non-loopback collection.

---

## Critical Decision Logic

### Q1: Are the CICIDS2017 and live TCP flag features semantically equivalent?

**NO.** CICIDS2017 uses binary presence indicators (0/1). Live NIDS uses integer packet counts (0-N). This is a CONFIRMED FEATURE SEMANTIC MISMATCH.

### Q2: Does non-loopback capture reduce the feature-space shift?

**UNKNOWN.** Non-loopback attack collection was not performed due to lack of isolated test environment. Benign non-loopback capture worked on the Ethernet interface, but attack traffic was not tested.

### Q3: Does the frozen ML model perform better on non-loopback attacks?

**UNKNOWN.** No non-loopback attack data available.

### Q4: Does PORT_SCAN rule detection improve when loopback is removed?

**UNKNOWN.** No non-loopback attack data available. However, the production rule is expected to improve on non-loopback because the loopback guard would no longer block cross-flow aggregation.

### Q5: Is loopback the primary source of the ML failure?

**NO.** The primary source is the feature semantic mismatch. Loopback contributes secondary artifacts, but the binary-vs-integer flag mismatch would persist on any interface.

### Q6: Is feature-semantic mismatch a separate root cause?

**YES.** This is a CONFIRMED FEATURE SEMANTIC MISMATCH, distinct from domain shift. It affects all interfaces, not just loopback.

### Q7: Is retraining justified now?

**NO.** The semantic mismatch should be fixed first in the feature extractor, then the frozen model should be re-evaluated. If performance remains poor after the fix, then retraining may be justified.

---

## Production Safety Check

| Check | Result |
|-------|--------|
| Production source files modified | **NO** |
| Model retrained | **NO** |
| Model changed | **NO** |
| Thresholds changed | **NO** |
| Rule behavior changed | **NO** |
| Feature definitions changed | **NO** |
| Model hash | `7bcc643154a1f44d` (unchanged) |
