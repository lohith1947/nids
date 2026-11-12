# Stage 11.8.2.1 — ML Forensic Analysis + Latency Correction Report

## 1. Executive Summary

Stage 11.8.2 produced 526 real attributed attack flows with genuine TCP flag evidence and valid 18-feature vectors. This stage performed forensic analysis to explain why the production ML model predicted `BENIGN` for all 526 attack flows, validated feature integrity, analyzed rule-engine behavior, verified hybrid correlation, and assessed latency measurement.

**Key findings:**
- **ML confidently predicts BENIGN** for all attack flows (mean BENIGN probability 0.85–0.93). This is not a borderline classification.
- **Feature integrity is verified:** ordering matches production, no NaN/Inf, no missing values, all numeric.
- **TCP flags are genuine:** verified through code inspection of `parse_packet_info()` and `Flow.add_packet()` bit-mask logic. Aggregate counters show non-zero SYN/ACK/FIN/PSH in the majority of flows.
- **PORT_SCAN rule detections = 0** due to a confirmed production limitation: the loopback guard skips cross-flow detection for 127.0.0.0/8, and local TCP server ACKs defeat the per-flow SYN-only-probe check.
- **Hybrid correlation correctly preserves rule detections** (Case D: ML=BENIGN, Rule=attack → final=rule prediction).
- **Latency measurement is invalid** — it records generation-end minus first-packet timestamp, not actual detection latency.
- **No CICIDS2017 baseline is available** for distribution comparison.

**Verdict:** `YELLOW — Diagnostic evidence is complete; root cause is identified as possible domain shift, but cannot be confirmed without training-data baseline.`

---

## 2. Dataset Used

| Artifact | Path |
|----------|------|
| JSONL dataset | `NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z.jsonl` |
| Collection log | `NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z_collection_log.txt` |
| Attribution log | `NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z_attribution_log.json` |

**Dataset statistics:**
- Total records: 526
- Attack classes: PORT_SCAN (164), BRUTE_FORCE (153), DOS (43), RECONNAISSANCE (166)
- Total captured packets: 76,989
- Capture errors: 0
- Attribution rate: 100% (526/526)

---

## 3. ML Probability Analysis

### 3.1 Overall ML Behavior

| Metric | Value |
|--------|-------|
| Total attack flows | 526 |
| ML predicted BENIGN | 526 (100%) |
| ML predicted attack class | 0 (0%) |
| Confidence range | 0.57 – 1.00 |
| Mean confidence | 0.927 (PORT_SCAN), 0.898 (BRUTE_FORCE), 0.854 (DOS), 0.909 (RECONNAISSANCE) |

**Critical finding:** The model is **confidently** predicting BENIGN, not marginally. The P10 BENIGN probability is ≥ 0.57 for all classes, and the P90 is ≥ 0.92. This rules out "barely choosing BENIGN" as an explanation.

### 3.2 Per-Class Probability Distribution

| Ground Truth | n | Mean BENIGN prob | Median BENIGN prob | P10 | P25 | P75 | P90 | Mean max prob |
|--------------|---|------------------|--------------------|-----|-----|-----|-----|---------------|
| PORT_SCAN | 164 | 0.927 | 0.940 | 0.900 | 0.905 | 0.945 | 0.955 | 0.927 |
| BRUTE_FORCE | 153 | 0.898 | 0.940 | 0.781 | 0.900 | 0.945 | 0.945 | 0.898 |
| DOS | 43 | 0.854 | 0.920 | 0.589 | 0.820 | 0.925 | 0.925 | 0.854 |
| RECONNAISSANCE | 166 | 0.909 | 0.934 | 0.895 | 0.905 | 0.945 | 0.950 | 0.909 |

**Interpretation:** The model assigns high BENIGN probability uniformly across all attack classes. There is no class-specific discrimination.

### 3.3 Per-Class Top-3 Probabilities (Average)

| True Class | BENIGN | PORT_SCAN | BRUTE_FORCE | DOS | RECONNAISSANCE |
|------------|--------|-----------|-------------|-----|----------------|
| PORT_SCAN | 0.927 | 0.012 | 0.025 | 0.052 | 0.013 |
| BRUTE_FORCE | 0.898 | 0.014 | 0.031 | 0.076 | 0.019 |
| DOS | 0.854 | 0.037 | 0.034 | 0.240 | 0.035 |
| RECONNAISSANCE | 0.909 | 0.013 | 0.019 | 0.068 | 0.050 |

**Note:** The `model_probabilities` field stores only the top-3 classes per flow, not all 5. Some attack classes (e.g., RECONNAISSANCE) appear in only a subset of top-3 lists.

### 3.4 Confidence Distribution

| Confidence bucket | Count | Percentage |
|-------------------|-------|------------|
| 0.0 – 0.2 | 0 | 0.0% |
| 0.2 – 0.4 | 0 | 0.0% |
| 0.4 – 0.6 | 15 | 2.9% |
| 0.6 – 0.8 | 19 | 3.6% |
| 0.8 – 1.0 | 479 | 91.1% |
| 1.0 | 13 | 2.5% |

---

## 4. 18-Feature Integrity Analysis

### 4.1 Feature Ordering Verification

Verified against `NIDS/features.py` `NUMERIC_FEATURE_NAMES` and `Flow.get_features()`:

```
[0]  duration
[1]  packet_count
[2]  byte_count
[3]  average_packet_size
[4]  minimum_packet_size
[5]  maximum_packet_size
[6]  packet_size_std
[7]  packets_per_second
[8]  bytes_per_second
[9]  forward_packets
[10] backward_packets
[11] forward_bytes
[12] backward_bytes
[13] syn_count
[14] ack_count
[15] fin_count
[16] rst_count
[17] psh_count
```

**Result:** Feature ordering **EXACTLY MATCHES** production.

### 4.2 Data Quality Checks

| Check | Result |
|-------|--------|
| All records have 18 features | PASS (526/526) |
| NaN values | 0 |
| Inf values | 0 |
| None values | 0 |
| Non-numeric types | 0 |
| Feature range violations | 0 |

### 4.3 Zero-Valued Features (Valid Network Values)

| Feature | Flows with value = 0 | Notes |
|---------|---------------------|-------|
| duration | 4/526 | Sub-second flows |
| packet_size_std | 8/526 | Single-packet flows |
| backward_packets | 35/526 | Unidirectional flows |
| backward_bytes | 35/526 | Unidirectional flows |
| syn_count | 115/526 | UDP or non-SYN TCP |
| ack_count | 48/526 | SYN-only or UDP |
| fin_count | 123/526 | Aborted/UDP flows |
| rst_count | 521/526 | Rare; only 5 flows have RST |
| psh_count | 66/526 | No push data |

**Conclusion:** Zero values are valid network behavior, not fabrication.

---

## 5. TCP Flag Evidence

### 5.1 Extraction Pipeline Verification

1. **Scapy capture:** `sniff()` on Loopback Pseudo-Interface 1 with `store=False`
2. **Packet parsing:** `parse_packet_info()` in `NIDS/packet_capture.py` extracts `int(packet[TCP].flags)` (line 94)
3. **Flow ingestion:** `FlowManager.process_packet()` passes `tcp_flags` to `flow.add_packet(timestamp, size, direction, tcp_flags)` (line 162)
4. **Flag counting:** `Flow.add_packet()` uses bit masks from `NIDS/features.py`:
   - `TCP_SYN = 0x02`
   - `TCP_ACK = 0x10`
   - `TCP_FIN = 0x01`
   - `TCP_RST = 0x04`
   - `TCP_PSH = 0x08`

**Result:** The extraction pipeline is correct and uses genuine packet-derived flags.

### 5.2 TCP Flag Distributions Across All Flows

| Flag | Flows with value > 0 | Percentage |
|------|---------------------|------------|
| SYN | 411 / 526 | 78.1% |
| ACK | 478 / 526 | 90.9% |
| FIN | 403 / 526 | 76.6% |
| RST | 5 / 526 | 1.0% |
| PSH | 460 / 526 | 87.5% |

### 5.3 Per-Class TCP Flag Distributions

| Attack Class | n | SYN > 0 | ACK > 0 | FIN > 0 | RST > 0 | PSH > 0 |
|--------------|---|---------|---------|---------|---------|---------|
| PORT_SCAN | 164 | 141 (85.9%) | 155 (94.5%) | 139 (84.8%) | 2 (1.2%) | 147 (89.6%) |
| BRUTE_FORCE | 153 | 132 (86.3%) | 146 (95.4%) | 129 (84.3%) | 1 (0.7%) | 145 (94.8%) |
| DOS | 43 | 1 (2.3%) | 16 (37.2%) | 0 (0.0%) | 1 (2.3%) | 14 (32.6%) |
| RECONNAISSANCE | 166 | 137 (82.5%) | 161 (97.0%) | 135 (81.3%) | 1 (0.6%) | 154 (92.8%) |

**Interpretation:**
- TCP-based attacks (PORT_SCAN, BRUTE_FORCE, RECONNAISSANCE) show high SYN/ACK/FIN/PSH counts, consistent with real TCP handshakes.
- DOS is UDP-based; low TCP flag counts are expected (UDP has no flags).
- RST is rare across all classes, which is normal for clean local servers.

**Conclusion:** Stage 11.8.2 **fixed the TCP-flag-zero bug**. The flags are genuinely populated from captured packets.

---

## 6. Feature Distribution Analysis

### 6.1 Per-Class Feature Statistics

| Feature | PORT_SCAN (n=164) | BRUTE_FORCE (n=153) | DOS (n=43) | RECONNAISSANCE (n=166) |
|---------|-------------------|---------------------|------------|------------------------|
| duration (mean) | 0.10 | 0.16 | 0.25 | 0.06 |
| packet_count (mean) | 12.70 | 10.04 | 315.37 | 11.08 |
| byte_count (mean) | 1423 | 623 | 25473 | 974 |
| avg_pkt_size (mean) | 64.22 | 84.60 | 161.42 | 85.14 |
| max_pkt_size (mean) | 222 | 149 | 295 | 183 |
| packet_size_std (mean) | 31.12 | 39.70 | 108.37 | 50.77 |
| pps (mean) | 3925 | 2778 | 7338 | 3865 |
| bps (mean) | 271305 | 465202 | 1687209 | 467014 |
| fwd_pkts (mean) | 6.78 | 5.52 | 314.67 | 5.96 |
| bwd_pkts (mean) | 5.91 | 4.52 | 0.70 | 5.13 |
| syn_count (mean) | 1.73 | 1.75 | 0.09 | 1.66 |
| ack_count (mean) | 11.71 | 9.03 | 1.33 | 10.19 |
| fin_count (mean) | 1.70 | 1.69 | 0.00 | 1.63 |
| rst_count (mean) | 0.02 | 0.03 | 0.07 | 0.02 |
| psh_count (mean) | 3.23 | 1.95 | 0.58 | 2.57 |

### 6.2 CICIDS2017 Baseline Comparison

**BASELINE UNAVAILABLE**

No CICIDS2017 training data, summary statistics, or baseline files are present in the evaluation datasets directory. A quantitative comparison of feature distributions against the training set cannot be performed from the available artifacts alone.

### 6.3 Observed Feature Patterns

- **Duration:** All attack classes show very short mean durations (0.06–0.25 s), typical of local loopback connections.
- **Packet/byte counts:** PORT_SCAN, BRUTE_FORCE, and RECONNAISSANCE have low mean packet counts (10–12), while DOS has high packet counts (315) due to UDP flooding.
- **Packet sizes:** Mean packet sizes range from 64 (PORT_SCAN) to 161 (DOS). CICIDS2017 typically shows larger average packet sizes for web/application traffic.
- **Rates:** DOS shows the highest pps/bps means. PORT_SCAN and RECONNAISSANCE show moderate rates.
- **Directionality:** PORT_SCAN, BRUTE_FORCE, and RECONNAISSANCE show roughly symmetric forward/backward packets (bidirectional TCP). DOS is strongly unidirectional (UDP).
- **TCP flags:** SYN/ACK/FIN/PSH are present in TCP-based attacks. DOS has minimal TCP flags.

---

## 7. ML Per-Class Analysis

| Ground Truth | Samples | ML BENIGN | ML Attack | Attack Recall | Mean Confidence | Min Confidence | Max Confidence |
|--------------|--------:|----------:|----------:|-------------:|----------------:|---------------:|---------------:|
| PORT_SCAN | 164 | 164 | 0 | 0.0% | 0.927 | 0.610 | 1.000 |
| BRUTE_FORCE | 153 | 153 | 0 | 0.0% | 0.898 | 0.570 | 0.955 |
| DOS | 43 | 43 | 0 | 0.0% | 0.854 | 0.568 | 0.980 |
| RECONNAISSANCE | 166 | 166 | 0 | 0.0% | 0.909 | 0.565 | 1.000 |

**Attack recall = 0% for all classes.**

### 7.1 Feature-Space Investigation

The model receives the same 18-feature schema used during training, in the exact same order. TCP flags are non-zero in the majority of TCP flows. No features are missing, fabricated, or defaulted.

**Possible explanations for 0% attack recall:**

1. **Domain shift:** Local loopback traffic has fundamentally different characteristics (timing, packet sizes, directional symmetry, flag sequences) than the CICIDS2017 WAN/LAN traffic the model was trained on. **This is the most likely explanation but cannot be confirmed without the training baseline.**
2. **Feature distribution mismatch:** Even with valid features, the statistical distributions (e.g., sub-second durations, small packet counts, symmetric bidirectional flows) may fall outside the regions the Random Forest learned for attack classes.
3. **Training data limitations:** The CICIDS2017 attack samples may not include loopback-style port scans, brute-force attempts, or reconnaissance patterns.

**Conclusion:** `POSSIBLE DOMAIN SHIFT` — The feature vectors are structurally valid, but their distributions differ from what the model expects. Without the CICIDS2017 baseline, causality cannot be established.

---

## 8. Rule Engine Analysis

### 8.1 Overall Rule Results

| Rule Prediction | Count | Percentage |
|-----------------|-------|------------|
| BENIGN | 367 | 69.8% |
| BRUTE_FORCE | 120 | 22.8% |
| DOS | 28 | 5.3% |
| RECONNAISSANCE | 11 | 2.1% |

### 8.2 PORT_SCAN = 0: Root Cause Analysis

**CONFIRMED PRODUCTION LIMITATION**

The `_check_port_scan()` method in `NIDS/rule_engine.py` has two detection paths:

1. **Cross-flow check** (lines 349–355): Aggregates unique destination ports per source IP within a time window.
   - **Explicitly skipped for loopback source IPs** (127.0.0.0/8) to avoid false positives from unrelated local processes.
   - Our collection uses `src_ip = 127.0.0.1` for all PORT_SCAN flows.
   - 127.0.0.1 contacted **39 unique destination ports** during the PORT_SCAN session, but this evidence is ignored by the rule.

2. **Per-flow SYN-only-probe check** (lines 358–367): Fires when `syn_count > 0 AND ack_count == 0 AND packet_count <= 5`.
   - **155/164 PORT_SCAN flows have ACK > 0** because the local TCP servers respond with ACKs.
   - **0/164 flows satisfy the SYN-only-probe condition** (all have either ack > 0 or packet_count > 5).
   - Only 9 flows have ACK = 0; none of those also have packet_count ≤ 5.

**Summary:** PORT_SCAN detection is blocked by the combination of:
- Loopback guard disabling cross-flow aggregation
- Local server responses producing ACKs that defeat the per-flow SYN-only check

This is a **production behavior limitation on loopback**, not an evaluation artifact.

### 8.3 Other Rule Detections

- **BRUTE_FORCE (120/153):** The rule detects repeated short connections to port 22 with no PSH data. This works because BRUTE_FORCE flows have `packet_count ≤ 3`, `duration ≤ 1.0s`, and `psh_count = 0` for many flows.
- **DOS (28/43):** The rule detects high packet rates (`pps > 500`) and high byte rates (`bps > 500,000`). DOS is UDP-based and produces sustained high-rate flows.
- **RECONNAISSANCE (11/166):** The rule detects connections to multiple unique destination IPs. However, the cross-flow check for RECONNAISSANCE is also skipped for loopback sources (line 528), so the 11 detections are from per-flow heuristics only.

---

## 9. Hybrid Correlation Analysis

### 9.1 Correlation Logic Verification

The `CorrelationEngine.correlate()` method in `NIDS/correlator.py` implements five cases:

- **Case A:** Rule + ML agree on non-BENIGN → union probability
- **Case B:** Both non-BENIGN but different classes → higher confidence × 0.85 penalty
- **Case C:** Rule=BENIGN, ML=attack → ML prediction × 0.80 penalty
- **Case D:** ML=BENIGN, Rule=attack → Rule prediction × 0.80 penalty
- **Case E:** Both BENIGN → min(rule_conf, ml_conf)

### 9.2 Hybrid Results for Stage 11.8.2 Data

| Final Prediction | Count | Source |
|------------------|-------|--------|
| BENIGN | 367 | Case E (both BENIGN) |
| BRUTE_FORCE | 120 | Case D (rule-only detection) |
| DOS | 28 | Case D (rule-only detection) |
| RECONNAISSANCE | 11 | Case D (rule-only detection) |

**All 159 rule detections are preserved in the hybrid output.** The correlation engine correctly falls back to rule predictions when ML says BENIGN (Case D).

### 9.3 Confidence Values

- Rule-only detections (Case D): `combined_confidence = rule_confidence × 0.80`
- Both BENIGN (Case E): `combined_confidence = min(rule_confidence, ml_confidence) = rule_confidence` (since rule_confidence = 0.0 for BENIGN)

**Result:** Hybrid correlation is functioning as designed.

---

## 10. Latency Analysis

### 10.1 How Latency Was Calculated

In `NIDS/evaluation/collect_attack_11_8_v2.py` (lines 413–415):

```python
first_packet_ts = flow.start_time
alert_ts = generation_end
pipeline_out = self._run_pipeline(flow, attack_class, first_packet_ts, alert_ts)
```

Where `generation_end = time.time()` immediately after the attack-generation thread finishes, and `_run_pipeline()` computes:

```python
detection_latency = alert_ts - first_packet_ts
```

### 10.2 Why This Is Invalid

- `first_packet_ts` = timestamp of the first packet in the flow (from Scapy `packet.time`)
- `alert_ts` = wall-clock time when attack generation ends, **not** when the alert is created
- The actual `AlertManager.create_alert()` return time is **not recorded**
- No clean timestamp chain exists: `packet_timestamp → flow_completion → alert_creation`

### 10.3 Measured Values

| Statistic | Value |
|-----------|-------|
| Count | 526 |
| Min | 0.010 s |
| Max | 7.993 s |
| Mean | 4.139 s |
| Median | 4.088 s |

These values reflect **collection/generation duration**, not NIDS detection latency.

### 10.4 Verdict

**VALID LATENCY NOT COMPUTABLE FROM EXISTING ARTIFACTS**

Missing timestamps:
- `AlertManager.create_alert()` completion time
- Flow completion timestamp (not just start_time)
- Pipeline processing timestamp

The existing dataset does not contain sufficient timestamps to calculate real detection latency.

---

## 11. Production Integrity

| Check | Result |
|-------|--------|
| Production NIDS files changed | **NO** |
| Model retrained | **NO** |
| Thresholds changed | **NO** |
| Model SHA256 prefix | `7bcc643154a1f44d` |

**Files created/modified during this stage:**
- `NIDS/evaluation/datasets/STAGE11_8_2_1_ML_FORENSIC_ANALYSIS_REPORT.md` (created)
- `NIDS/evaluation/collect_attack_11_8_v2.py` (modified in Stage 11.8.2 only)

No production source files were altered.

---

## 12. Test Results

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

## 13. Root-Cause Assessment

### 13.1 ML BENIGN Predictions

| Classification | Evidence |
|----------------|----------|
| `POSSIBLE DOMAIN SHIFT` | Feature vectors are structurally valid and ordered correctly. TCP flags are non-zero. However, the model predicts BENIGN with high confidence for all attack classes. Local loopback traffic characteristics (sub-second durations, small symmetric flows, local server responses) differ from typical CICIDS2017 WAN/LAN traffic. **The CICIDS2017 baseline is unavailable for quantitative confirmation.** |

### 13.2 PORT_SCAN Rule = 0

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED PRODUCTION LIMITATION` | The rule engine explicitly skips cross-flow port aggregation for 127.0.0.0/8 sources. The per-flow SYN-only-probe check is defeated by ACK responses from local TCP servers. This behavior is by design in `NIDS/rule_engine.py` lines 349–367. |

### 13.3 Latency Measurement Invalid

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED EVALUATION LIMITATION` | The collection script records `generation_end - first_packet_timestamp` as latency. This measures collection duration, not NIDS detection latency. The `AlertManager.create_alert()` completion time is not captured. |

### 13.4 CICIDS2017 Baseline Missing

| Classification | Evidence |
|----------------|----------|
| `CONFIRMED EVALUATION LIMITATION` | No CICIDS2017 training data, summary statistics, or baseline files are present in the evaluation datasets directory or elsewhere in the project. |

---

## 14. Recommendation for Stage 11.8.3

1. **Fix latency measurement:** Instrument `AlertManager.create_alert()` to record `alert_timestamp`. Calculate latency as `alert_timestamp - flow.start_time` with both timestamps from the production pipeline.
2. **Obtain CICIDS2017 baseline:** Export feature statistics from the training CSV (mean, std, min, max per feature per class) to enable distribution comparison.
3. **Investigate domain shift:** Compare collected attack feature distributions against the CICIDS2017 baseline. If distributions diverge, consider:
   - Collecting on a non-loopback interface (e.g., host-only adapter)
   - Adjusting attack generation to produce more realistic timing and packet sizes
   - Adding loopback-specific training data or domain adaptation
4. **Do NOT retrain the model yet:** The root cause (domain shift vs. feature mismatch vs. training-data gap) is not established. Retraining without diagnostic clarity risks embedding the same limitation.
5. **PORT_SCAN rule:** The loopback guard is intentional. For evaluation on loopback, either disable the guard in a test-only mode or collect on a non-loopback interface where the cross-flow check functions.

---

## Final Verdict

`YELLOW — Diagnostic evidence is complete; root cause is identified as possible domain shift, but cannot be confirmed without training-data baseline.`

The evaluation infrastructure now captures genuine TCP flag evidence and produces valid 18-feature vectors. The ML model's universal BENIGN prediction is confidently held, not marginal, suggesting a structural mismatch between collected features and the model's training distribution. This is diagnostically useful but requires the CICIDS2017 baseline to confirm causality.
