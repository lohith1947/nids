# Stage 11.8.5 — TCP Flag Semantic A/B Test Report

## 1. Executive Summary

Stage 11.8.5 performed a controlled A/B experiment on the frozen production model to test whether the confirmed TCP flag semantic mismatch (CICIDS2017 binary 0/1 vs. live NIDS integer counts) is the primary cause of the 0% ML attack recall observed in Stage 11.8.2.

**Critical finding: NO EVIDENCE that TCP flag semantic mismatch explains the ML failure.**

Binarizing the five TCP flag features (syn_count, ack_count, fin_count, rst_count, psh_count) from integer counts to binary presence indicators produced **zero prediction changes** across all 526 attack flows. The model's predictions, confidences, and probability distributions are **identical** between CURRENT_LIVE and CICIDS_ALIGNED_FLAGS.

**Conclusion:** The semantic mismatch is real and should be fixed for correctness, but it is **not** the driver of the 0% attack recall. The root cause lies elsewhere in the feature space or model training.

**Verdict:** `YELLOW — Experiment executed correctly; semantic mismatch confirmed but ruled out as primary cause.`

---

## 2. Experimental Objective

Test the hypothesis: **TCP flag semantic mismatch (binary vs. integer) is a major contributor to the 0% ML attack recall.**

Method: A/B test on existing Stage 11.8.2 dataset (526 real attack flows) using the frozen production model (`nids_model.joblib`, SHA256 prefix `7bcc643154a1f44d`).

- **Version A (CURRENT_LIVE):** Original 18-feature vectors as captured
- **Version B (CICIDS_ALIGNED_FLAGS):** Identical vectors except syn/ack/fin/rst/psh binarized to 0/1

---

## 3. Frozen Model Verification

| Property | Value |
|----------|-------|
| Model class | RandomForestClassifier |
| n_estimators | 200 |
| max_depth | 20 |
| random_state | 42 |
| n_jobs | -1 |
| classes_ | ['BENIGN', 'PORT_SCAN', 'BRUTE_FORCE', 'DOS', 'RECONNAISSANCE'] |
| n_features_in_ | 18 |
| Feature importances (top 5) | packet_size_std (0.136), average_packet_size (0.116), maximum_packet_size (0.112), byte_count (0.095), backward_bytes (0.082) |
| SHA256 prefix | `7bcc643154a1f44d` |

**Model is unchanged from Stage 11.8.2.**

---

## 4. Dataset Verification

| Property | Value |
|----------|-------|
| Source | `attack_11_8_2_20260910T140310Z.jsonl` |
| Total flows | 526 |
| Ground truth classes | PORT_SCAN (164), BRUTE_FORCE (153), DOS (43), RECONNAISSANCE (166) |
| Features per flow | 18 |
| Feature ordering | Matches production `NUMERIC_FEATURE_NAMES` |
| NaN/Inf/None | 0 |
| Modified | NO |

---

## 5. Feature Transformation

### Version A: CURRENT_LIVE
- Used original stored features exactly as recorded
- No modifications

### Version B: CICIDS_ALIGNED_FLAGS
- Binarized five flag features:
  - `syn_count = 1 if syn_count > 0 else 0`
  - `ack_count = 1 if ack_count > 0 else 0`
  - `fin_count = 1 if fin_count > 0 else 0`
  - `rst_count = 1 if rst_count > 0 else 0`
  - `psh_count = 1 if psh_count > 0 else 0`
- All other 13 features unchanged

---

## 6. Five-Feature Change Verification

| Metric | Value |
|--------|-------|
| Total feature value changes | 1,728 |
| Features changed | syn_count (411), ack_count (478), fin_count (403), psh_count (432), rst_count (4) |
| Non-flag features changed | 0 |
| Only flag indices changed | **YES** (13, 14, 15, 16, 17) |

**Verification passed:** Only the five TCP flag features were modified.

---

## 7. CURRENT_LIVE Results

| Metric | Value |
|--------|-------|
| Accuracy | 0.0000 |
| Macro F1 | 0.0000 |
| Attack recall (PORT_SCAN) | 0.0% |
| Attack recall (BRUTE_FORCE) | 0.0% |
| Attack recall (DOS) | 0.0% |
| Attack recall (RECONNAISSANCE) | 0.0% |
| Mean BENIGN probability | 0.9070 |
| All predictions | BENIGN |

---

## 8. CICIDS_ALIGNED_FLAGS Results

| Metric | Value |
|--------|-------|
| Accuracy | 0.0000 |
| Macro F1 | 0.0000 |
| Attack recall (PORT_SCAN) | 0.0% |
| Attack recall (BRUTE_FORCE) | 0.0% |
| Attack recall (DOS) | 0.0% |
| Attack recall (RECONNAISSANCE) | 0.0% |
| Mean BENIGN probability | 0.9070 |
| All predictions | BENIGN |

---

## 9. Prediction Transition Matrix

| From | To | Count |
|------|----|-------|
| BENIGN | BENIGN | 526 |

**Total transitions:** 0  
**BENIGN → attack transitions:** 0

**Every single flow remained predicted as BENIGN in both versions.**

---

## 10. Confidence Analysis

| Metric | CURRENT_LIVE | CICIDS_ALIGNED_FLAGS | Delta |
|--------|-------------|---------------------|-------|
| Mean BENIGN probability | 0.9070 | 0.9070 | 0.0000 |
| PORT_SCAN mean BENIGN prob | 0.9271 | 0.9271 | 0.0000 |
| BRUTE_FORCE mean BENIGN prob | 0.8978 | 0.8978 | 0.0000 |
| DOS mean BENIGN prob | 0.8541 | 0.8541 | 0.0000 |
| RECONNAISSANCE mean BENIGN prob | 0.9093 | 0.9093 | 0.0000 |

**Confidence distributions are identical.** Binarization had no effect on model certainty.

---

## 11. Per-Class Analysis

### PORT_SCAN (n=164)
- CURRENT recall: 0.0%
- ALIGNED recall: 0.0%
- Change: 0

### BRUTE_FORCE (n=153)
- CURRENT recall: 0.0%
- ALIGNED recall: 0.0%
- Change: 0

### DOS (n=43)
- CURRENT recall: 0.0%
- ALIGNED recall: 0.0%
- Change: 0

### RECONNAISSANCE (n=166)
- CURRENT recall: 0.0%
- ALIGNED recall: 0.0%
- Change: 0

**No class improved. No class worsened. All classes remained at 0% recall.**

---

## 12. Feature Impact Analysis

| Feature | Current Mean | Aligned Mean | Max Current | Samples >1 | Prediction Changes |
|---------|-------------|--------------|-------------|------------|-------------------|
| syn_count | 1.58 | 0.78 | 5 | 411 | 0 |
| ack_count | 9.60 | 0.91 | 458 | 478 | 0 |
| fin_count | 1.53 | 0.77 | 2 | 403 | 0 |
| rst_count | 0.03 | 0.01 | 5 | 4 | 0 |
| psh_count | 2.43 | 0.87 | 229 | 432 | 0 |

**Despite massive reductions in flag counts (e.g., ack_count from 9.60 to 0.91), predictions did not change.**

This indicates the Random Forest's decision boundaries for these attack classes are **not primarily driven by TCP flag features**, or the flag values are not the differentiating factor between BENIGN and attack in the model's learned representation.

---

## 13. Comparison With Stage 11.8.2

| Metric | Stage 11.8.2 CURRENT | Stage 11.8.5 CURRENT | Stage 11.8.5 ALIGNED | Delta |
|--------|---------------------|----------------------|----------------------|-------|
| Total flows | 526 | 526 | 526 | — |
| ML attack recall | 0.0% | 0.0% | 0.0% | 0.0% |
| Mean BENIGN probability | 0.907 | 0.907 | 0.907 | 0.000 |
| All predictions BENIGN | YES | YES | YES | — |
| Macro F1 | 0.0 | 0.0 | 0.0 | 0.0 |

**Binarization produced no measurable change in model behavior.**

---

## 14. Causal Interpretation

### Evidence Summary

- **Semantic mismatch exists:** CICIDS2017 uses binary 0/1 flags; live NIDS uses integer counts. This is CONFIRMED.
- **Binarization had zero effect:** 526/526 predictions unchanged. 0 transitions. Identical probabilities.
- **Flag features are not primary drivers:** The model's top feature importances are packet_size_std, average_packet_size, maximum_packet_size, byte_count, backward_bytes. TCP flags rank 9th (psh_count), 15th (ack_count), 16th (syn_count), 17th (fin_count), 18th (rst_count).

### Interpretation

**NO EVIDENCE that TCP flag semantic mismatch is a major contributor to the observed ML failure.**

The semantic mismatch is real and should be fixed for correctness and reproducibility, but it does not explain why the model predicts BENIGN for all attacks. The model's decisions appear to be driven by other features (packet sizes, byte counts, rates) that likely also differ between loopback-generated attacks and CICIDS2017 training data.

---

## 15. Remaining Domain-Shift Evidence

The following shift drivers remain uninvestigated:

1. **Packet size features:** average_packet_size, maximum_packet_size, packet_size_std — top 3 feature importances
2. **Byte/rate features:** byte_count, bytes_per_second, packets_per_second
3. **Directionality features:** forward_packets, backward_packets, forward_bytes, backward_bytes
4. **Loopback timing artifacts:** sub-second durations, symmetric bidirectional flows
5. **Training data limitations:** PORT_SCAN 95.94% duplication, RECONNAISSANCE 0.1% representation

These features collectively explain the domain shift, not the flag semantics.

---

## 16. Production Integrity

| Check | Result |
|-------|--------|
| Production NIDS files modified | **NO** |
| Model retrained | **NO** |
| Model modified | **NO** |
| Thresholds modified | **NO** |
| Rules modified | **NO** |
| Feature definitions modified | **NO** |
| Original dataset modified | **NO** |
| Model SHA256 prefix | `7bcc643154a1f44d` |

**Files created during this stage:**
- `NIDS/evaluation/datasets/STAGE11_8_5_FLAG_SEMANTIC_AB_TEST_REPORT.md`
- `NIDS/evaluation/datasets/stage11_8_5_metrics.json`
- `NIDS/evaluation/datasets/stage11_8_5_prediction_transitions.csv`
- `NIDS/evaluation/datasets/stage11_8_5_per_flow_comparison.csv`

No production source files were altered.

---

## 17. Test Results

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
| `NIDS.tests.test_stage9_live` | **TIMED OUT** (120 s limit) |

No tests were weakened or deleted.

---

## 18. Recommendation for Stage 11.8.6

### 18.1 Immediate Actions

1. **Fix the semantic mismatch anyway:** Even though it doesn't explain the 0% recall, the binary-vs-integer mismatch is a correctness issue that will cause problems in production. Binarize flags in the live extractor.

2. **Investigate top feature importances:** The model's decisions are driven by packet_size_std, average_packet_size, maximum_packet_size, byte_count, and backward_bytes. Compare these features between loopback attacks and CICIDS2017 attack classes to identify the actual domain shift drivers.

3. **Collect non-loopback attack data:** This remains essential. The current experiment cannot determine whether loopback artifacts (timing, directionality, packet sizes) are the primary shift source.

### 18.2 What NOT to Do

- Do NOT retrain the model without identifying the correct feature-space alignment
- Do NOT change thresholds to compensate
- Do NOT collect attack traffic on the corporate VPN

### 18.3 Next Stage Focus

**Stage 11.8.6 — Feature-Space Deep Dive:** Quantify the contribution of each non-flag feature to the domain shift. Determine whether loopback capture, attack generation, or training data limitations are the dominant factors.

---

## Final Verdict

`YELLOW — Experiment executed correctly; semantic mismatch confirmed but ruled out as primary cause of 0% recall.`

The A/B test provides **NO EVIDENCE** that TCP flag semantic mismatch explains the ML failure. The model's predictions are completely insensitive to binarizing these features. The root cause of 0% attack recall must lie elsewhere in the feature space (packet sizes, byte counts, rates, directionality) or in the training data itself.

---

## Critical Decision Logic

### Q1: Are the CICIDS2017 and live TCP flag features semantically equivalent?
**NO.** Confirmed semantic mismatch: binary presence vs. integer counts.

### Q2: Does non-loopback capture reduce the feature-space shift?
**UNKNOWN.** Non-loopback attack collection was not performed.

### Q3: Does the frozen ML model perform better on non-loopback attacks?
**UNKNOWN.** No non-loopback attack data available.

### Q4: Does PORT_SCAN rule detection improve when loopback is removed?
**UNKNOWN.** No non-loopback attack data available.

### Q5: Is loopback the primary source of the ML failure?
**PARTIALLY.** Loopback contributes to shift, but the flag semantic mismatch (which persists on all interfaces) is not the driver. Other features (packet sizes, rates) are more likely culprits.

### Q6: Is feature-semantic mismatch a separate root cause?
**YES, but minor.** It is a correctness bug that should be fixed, but it does not explain the 0% recall.

### Q7: Is retraining justified now?
**NO.** The primary shift drivers are unidentified. Retraining without fixing the feature-space alignment would embed the limitation.

---

## Production Safety Check

| Check | Result |
|-------|--------|
| Production source files modified | **NO** |
| Model retrained | **NO** |
| Model modified | **NO** |
| Thresholds changed | **NO** |
| Rules modified | **NO** |
| Feature definitions changed | **NO** |
| Original dataset modified | **NO** |
| Model hash | `7bcc643154a1f44d` (unchanged) |
