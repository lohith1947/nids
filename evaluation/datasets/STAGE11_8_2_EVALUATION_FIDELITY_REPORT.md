# Stage 11.8.2 — Evaluation Fidelity Report

## 1. Executive Summary

Stage 11.8.2 replaced synthetic feature injection with Scapy-based packet capture on `Loopback Pseudo-Interface 1` fed through the production `FlowManager`. The collection produced **526 attributed attack flows** (164 PORT_SCAN, 153 BRUTE_FORCE, 43 DOS, 166 RECONNAISSANCE) from **76,989 raw captured packets** with **zero capture errors** and **100% attribution rate**.

Direct evidence confirms the previous Stage 11.8 TCP-flag deficiency is resolved: **411/526 flows have SYN > 0, 478/526 have ACK > 0, 403/526 have FIN > 0, 5/526 have RST > 0, and 460/526 have PSH > 0**. The 18-feature vectors match the production `Flow.get_features()` ordering.

However, the ML model predicted `BENIGN` for **all 526 attack flows** (high confidence, 0.57–1.00). Detection-latency values in the dataset are **invalid** because they measure generation-end minus first-packet timestamp, not actual alert creation time. Production files were not modified and the model was not retrained.

**Verdict: YELLOW — Evaluation improvements are partially complete; further fidelity work is required.**

---

## 2. Previous Stage 11.8 Problems

The Stage 11.8 evaluation recorded **all TCP flags as zero** because features were synthesized without real packet capture. This prevented the ML model and rule engine from observing actual TCP handshake patterns (SYN, ACK, PSH, FIN, RST), undermining detection fidelity for connection-oriented attacks.

---

## 3. Stage 11.8.2 Changes

- **Scapy capture on Loopback Pseudo-Interface 1** with a threaded sniff loop (`sniff` + `stop_filter`) instead of inline blocking.
- **Production `FlowManager.process_packet()`** receives live Scapy packets; `parse_packet_info()` extracts `int(packet[TCP].flags)` and passes it to `Flow.add_packet()`.
- **Local TCP/UDP server threads** provide real responders for generated attack traffic.
- **Four attack classes** generated with randomized payloads and jitter: PORT_SCAN, BRUTE_FORCE, DOS (UDP flood), RECONNAISSANCE (multi-host).
- **Pipeline execution**: FlowManager → RuleEngine → CorrelationEngine → RiskScorer → AlertManager.
- **Outputs**: JSONL dataset (`attack_11_8_2_20260910T140310Z.jsonl`), collection log, attribution log.

---

## 4. Capture Validation

| Metric | Value |
|--------|-------|
| Total flows | 526 |
| Total captured packets | 76,989 |
| Capture errors | 0 |
| Attribution success | 526 / 526 (100%) |
| Unattributed flows | 0 |
| Interface | Loopback Pseudo-Interface 1 |

All flows are attributed with reason `scapy_capture_flowmanager`.

---

## 5. TCP Flag Validation

Direct inspection of the `syn_count`, `ack_count`, `fin_count`, `rst_count`, and `psh_count` fields (feature indices 13–17) in the 526 JSONL records:

| Flag | Flows with value > 0 | Percentage |
|------|---------------------|------------|
| SYN | 411 / 526 | 78.1% |
| ACK | 478 / 526 | 90.9% |
| FIN | 403 / 526 | 76.6% |
| RST | 5 / 526 | 1.0% |
| PSH | 460 / 526 | 87.5% |

**Per-class breakdown:**

| Attack Class | SYN > 0 | ACK > 0 | FIN > 0 | RST > 0 | PSH > 0 |
|--------------|---------|---------|---------|---------|---------|
| PORT_SCAN (164) | 141 | 155 | 139 | 2 | 147 |
| BRUTE_FORCE (153) | 132 | 146 | 129 | 1 | 145 |
| DOS (43) | 1 | 16 | 0 | 1 | 14 |
| RECONNAISSANCE (166) | 137 | 161 | 135 | 1 | 154 |

**Conclusion:** The Stage 11.8.2 collection **fixed the TCP-flag-zero bug**. TCP flags are non-zero and varied across the majority of flows. The DOS class shows low flag counts because it is UDP-based (no TCP flags by definition).

---

## 6. 18-Feature Validation

The JSONL feature vectors contain **exactly 18 numeric values** per record. The ordering matches `NIDS/features.py` `NUMERIC_FEATURE_NAMES` and `Flow.get_features()`:

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

No features are `None` or out of the range `(-1e9, 1e9)`. Zero-valued features are valid network values (e.g., `duration=0` for sub-second flows, `rst_count=0` for normal closures). **No features appear fabricated or defaulted.**

---

## 7. Attribution Validation

- **Total attribution log entries:** 526
- **Status:** `ATTRIBUTED` for all 526 entries (100%)
- **Reason:** `scapy_capture_flowmanager` for all entries
- **Protocol match (expected vs. actual):** 489 / 526 (93.5%)
  - 37 mismatches are attributable to bidirectional FlowManager canonical-key behavior; they do not indicate unattributed traffic.

---

## 8. Ground-Truth Independence

Ground-truth labels (`PORT_SCAN`, `BRUTE_FORCE`, `DOS`, `RECONNAISSANCE`) are assigned by the collection script based on the generator function used. They are **not** derived from model predictions, rule predictions, correlation results, risk scores, or alert outcomes.

---

## 9. Attack Dataset Composition

| Class | Flows | Percentage |
|-------|-------|------------|
| PORT_SCAN | 164 | 31.2% |
| BRUTE_FORCE | 153 | 29.1% |
| DOS | 43 | 8.2% |
| RECONNAISSANCE | 166 | 31.6% |
| **Total** | **526** | **100%** |

**Protocol distribution:**
- TCP (proto 6): 478 flows (90.9%)
- UDP (proto 17): 48 flows (9.1%)

---

## 10. ML Results

| Metric | Value |
|--------|-------|
| Total attack flows | 526 |
| ML predicted BENIGN | 526 (100%) |
| ML predicted any attack class | 0 (0%) |
| ML confidence range | 0.57 – 1.00 |
| ML confidence buckets | 0.4–0.6: 15; 0.6–0.8: 19; 0.8–1.0: 479; 1.0: 13 |

**Per-class top-3 ML probabilities (average):**

| True Class | BENIGN | PORT_SCAN | BRUTE_FORCE | DOS | RECONNAISSANCE |
|------------|--------|-----------|-------------|-----|----------------|
| PORT_SCAN | 0.927 | 0.012 | 0.025 | 0.052 | 0.013 |
| BRUTE_FORCE | 0.898 | 0.014 | 0.031 | 0.076 | 0.019 |
| DOS | 0.854 | 0.037 | 0.034 | 0.240 | 0.035 |
| RECONNAISSANCE | 0.909 | 0.013 | 0.019 | 0.068 | 0.050 |

**Investigation findings:**

- **Feature ordering:** Verified to match production `Flow.get_features()` exactly.
- **TCP flags in features:** Non-zero SYN/ACK/FIN/PSH values are present in the majority of TCP flows, so flags were not universally zeroed out.
- **Feature validity:** All 18 features are numeric, within range, and contain no `None` values.
- **CICIDS2017 distribution:** INSUFFICIENT EVIDENCE. The training artifacts (CICIDS2017 CSV or summary statistics) are not present in the evaluation datasets directory, so a quantitative comparison cannot be performed from the available files alone.
- **Conclusion on ML performance:** The model predicts `BENIGN` for every attack flow. Because the feature vectors are structurally valid and the model is known to predict non-BENIGN classes on synthetically crafted inputs (verified in `test_regression`), this indicates either (a) the collected attack traffic falls outside the CICIDS2017 training distribution, or (b) the attack generation on loopback produces feature signatures the model has not learned. **The available artifacts do not establish which cause is dominant.**

---

## 11. Rule Results

| Rule Prediction | Count | Percentage |
|-----------------|-------|------------|
| BENIGN | 367 | 69.8% |
| BRUTE_FORCE | 120 | 22.8% |
| DOS | 28 | 5.3% |
| RECONNAISSANCE | 11 | 2.1% |

The rule engine detected **159 of 526 attack flows** (30.2%):
- PORT_SCAN: 0 detected by rules
- BRUTE_FORCE: 120 detected
- DOS: 28 detected
- RECONNAISSANCE: 11 detected

Rule confidence is **0.0 for all 367 BENIGN predictions** and non-zero for detected attacks.

---

## 12. Hybrid Results

The correlation engine computes `final_prediction = min(rule_confidence, ml_confidence)` for disagreement cases. Because ML confidence is high (≥ 0.57) for all flows and rule confidence is 0.0 for 367 flows, the hybrid prediction is `BENIGN` for **all 526 records**.

---

## 13. Latency Measurement

**How latency was calculated in the collection script:**

```python
first_packet_ts = flow.start_time
alert_ts = generation_end
detection_latency = alert_ts - first_packet_ts
```

Where `generation_end = time.time()` immediately after the attack-generation thread finishes.

**Assessment:** This is **not detection latency**. It measures the wall-clock interval from the first captured packet to the end of attack generation. No clean `packet_timestamp → flow_completion → alert_creation` timestamp chain is recorded. The `AlertManager.create_alert()` return time is not captured; `alert_ts` is a surrogate.

**Result:** Latency measurement remains **insufficient**. The values (min 0.010 s, max 7.993 s, avg 4.139 s) reflect collection duration, not NIDS detection latency.

---

## 14. Dataset Diversity and Duplicate Analysis

| Metric | Value |
|--------|-------|
| Total records | 526 |
| Unique 18-feature vectors | 523 |
| Duplicate records | 3 |
| Duplicate percentage | 0.57% |
| Cross-class identical vectors | 0 |

**Duplicate details:**
- Record 313 duplicates record 312 (BRUTE_FORCE): `[0.0, 1, 233, 233.0, 233, 233, 0.0, 1.0, 233.0, 1, 0, 233, 0, 0, 0, 0, 0, 0]`
- Record 314 duplicates record 312 (BRUTE_FORCE): identical vector
- Record 370 duplicates record 369 (RECONNAISSANCE): `[0.000326..., 4, 1272, 318.0, 44, 944, 370.17..., 12264.04..., 3899966.87..., 2, 2, 284, 988, 0, 4, 0, 0, 2]`

Duplicates were **not removed** per instructions. The duplicate rate is low (0.57%) and cross-class duplicates are absent.

---

## 15. Production Integrity

| Check | Result |
|-------|--------|
| Production NIDS files changed | **NO** |
| Model retrained | **NO** |
| Thresholds changed | **NO** |
| Model SHA256 prefix | `7bcc643154a1f44d` |

Only `NIDS/evaluation/collect_attack_11_8_v2.py` was created/modified. No production source files (`NIDS/flow.py`, `NIDS/flow_manager.py`, `NIDS/model.py`, `NIDS/rule_engine.py`, `NIDS/correlator.py`, `NIDS/risk_scorer.py`, `NIDS/alerts.py`, `NIDS/features.py`, etc.) were altered.

---

## 16. Test Results

| Test Suite | Result |
|------------|--------|
| `NIDS.tests.test_evaluation` | **24 / 24 PASSED** |
| `NIDS.tests.test_regression` | **3 / 3 PASSED** |
| `NIDS.tests.test_stage10` | **17 / 17 PASSED** |
| `NIDS.tests.test_rule_engine` | **11 / 11 PASSED** |
| `NIDS.tests.test_correlator` | **7 / 7 PASSED** |
| `NIDS.tests.test_risk_scorer` | **18 / 18 PASSED** |
| `NIDS.tests.test_pipeline` | **25 / 25 PASSED** |
| `NIDS.tests.test_alerts` | **17 / 17 PASSED** |
| `NIDS.tests.test_concurrency` | **12 / 12 PASSED** |
| `NIDS.tests.test_attribution_regression` | **10 / 10 PASSED** |
| `NIDS.tests.test_dashboard` | **18 / 18 PASSED** |
| `NIDS.tests.test_stage9_live` | **TIMED OUT** (120 s limit exceeded; requires live multi-interface traffic generation) |

No tests were weakened or deleted.

---

## 17. Remaining Limitations

1. **ML misclassification:** All 526 attack flows are classified as `BENIGN`. The root cause (distribution shift vs. feature extraction mismatch) is **undetermined** from current artifacts.
2. **Invalid latency:** Detection latency is not measured correctly; the dataset contains generation-duration proxies instead.
3. **CICIDS2017 baseline missing:** No training-data summary is available for distribution comparison.
4. **Loopback artifacts:** Some bidirectional flows on loopback may exhibit atypical timing and flag sequences compared to real Ethernet.
5. **Limited DOS volume:** Only 43 DOS flows were captured (UDP flood), which may under-represent high-rate DoS characteristics.
6. **Stage 9 live test incomplete:** The end-to-end live test could not be executed within the timeout.

---

## 18. Recommendation for Stage 11.8.3

1. **Fix latency measurement:** Record `alert_timestamp` from `AlertManager.create_alert()` (or inject a deterministic clock) so latency is `alert_ts - first_packet_ts` with both timestamps from the production pipeline.
2. **Investigate ML zero-detection rate:** Export per-class feature statistics and compare against the CICIDS2017 training summary. If the collected features are outside the training distribution, redesign attack generation or collect on a non-loopback interface.
3. **Add a non-loopback capture mode:** Loopback timing and TCP behavior differ from real networks; a secondary capture on a physical or VM network interface would improve ecological validity.
4. **Increase DOS sample size:** Generate more UDP/TCP flood flows to ensure the rule engine and ML model have sufficient attack examples for calibration.
5. **Run Stage 9 live test with extended timeout:** Ensure the full end-to-end pipeline passes on live traffic before proceeding.

---

## Final Verdict

`YELLOW — Evaluation improvements are partially complete; further fidelity work is required`

The capture infrastructure now preserves real TCP flag evidence and produces valid 18-feature vectors, resolving the critical Stage 11.8 bug. However, the ML model does not detect any of the 526 attacks, latency measurement is invalid, and the CICIDS2017 distribution comparison is absent. These gaps prevent a GREEN verdict.
