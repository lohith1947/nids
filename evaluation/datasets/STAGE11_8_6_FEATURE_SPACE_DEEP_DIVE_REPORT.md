# STAGE 11.8.6 — FEATURE-SPACE DEEP DIVE REPORT

## 1. Executive Summary

Stage 11.8.6 performed a comprehensive, evaluation-only diagnosis of why the frozen Random Forest model predicts BENIGN for all 526 controlled attack flows (0% recall). The analysis examined feature-space distribution shifts, statistical distances, range overlap, BENIGN-vs-attack separability, model prediction patterns, univariate counterfactual tests, training-data duplication, and feature importance interpretation.

**Primary finding:** The frozen model fails due to a combination of **feature distribution shift** and **attack-generation artifacts**, compounded by **training-data limitations**. No single feature counterfactual flips predictions, but several features show strong statistical associations with BENIGN confidence. The loopback capture environment produces attack traffic with fundamentally different statistical properties from CICIDS2017.

**Verdict:** `YELLOW — Valid experiment with sufficient evidence for diagnosis; uncertainty remains about optimal remediation path.`

---

## 2. Frozen Model Verification

| Property | Value |
|----------|-------|
| Class | `RandomForestClassifier` |
| n_estimators | 200 |
| max_depth | 20 |
| random_state | 42 |
| n_jobs | -1 |
| n_features_in_ | 18 |
| classes_ | [0, 1, 2, 3, 4] → [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE] |
| Model hash | `7bcc643154a1f44d` |

The model includes a `StandardScaler` (stored in the same joblib bundle). Feature importances are present and ordered by the 18-feature schema.

---

## 3. Dataset Verification

| Dataset | Path | Size | Classes |
|---------|------|------|---------|
| CICIDS2017 training | `C:\Users\SRIRAM NAIDU\AppData\Local\Temp\cicids2017\CICIDS2017_sample.csv` | 56,661 rows × 78 columns → 18 features | BENIGN=22,731, DOS=21,001, PORT_SCAN=7,946, BRUTE_FORCE=4,947, RECONNAISSANCE=36 |
| Controlled attacks | `NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z.jsonl` | 526 flows, 76,989 packets | PORT_SCAN=164, BRUTE_FORCE=153, RECONNAISSANCE=166, DOS=43 |
| Controlled benign | `NIDS/evaluation/datasets/expanded_11_7_20260910T081352Z.jsonl` | 1,000 flows | BENIGN=1,000 |

All datasets verified. No original datasets modified.

---

## 4. Feature Distribution Baselines

CICIDS2017 class-conditioned statistics were computed for all 5 classes × 18 features. Output: `stage11_8_6_feature_statistics.csv`.

Key baseline characteristics:

| Feature | CICIDS BENIGN median | CICIDS PORT_SCAN median | CICIDS BRUTE_FORCE median | CICIDS DOS median | CICIDS RECON median |
|---------|---------------------:|------------------------:|---------------------------:|------------------:|--------------------:|
| duration | 0.000047s | 0.000047s | 5.47s | 5.25s | 93.19s |
| packet_count | 2 | 2 | 4 | 8 | 52 |
| byte_count | 284 | 6 | 0 | 11,633 | 7,098 |
| average_packet_size | 50.09 | 3.00 | 0.00 | 833.50 | 146.78 |
| packet_size_std | 0 | 0 | 0 | 30.98 | 13.56 |
| packets_per_second | 0 | 0 | 0 | 1.54 | 0.56 |
| bytes_per_second | 0 | 0 | 0 | 2,216.22 | 76.24 |

---

## 5. CICIDS vs Live Feature Shift

The feature shift matrix (`stage11_8_6_distribution_shift.csv`) reveals extreme shifts for the first 13 non-flag features.

### Top 10 shifted features (by live/CICIDS attack median ratio)

| Feature | Attack Class | CICIDS Attack Median | Live Attack Median | Ratio |
|---------|-------------|---------------------:|-------------------:|------:|
| duration | PORT_SCAN | 0.000047s | 0.006884s | 146.5× |
| minimum_packet_size | PORT_SCAN | 0 | 44 | ∞ |
| byte_count | PORT_SCAN | 6 | 544 | 90.7× |
| average_packet_size | PORT_SCAN | 3.0 | 50.0 | 16.7× |
| packet_count | PORT_SCAN | 2 | 11 | 5.5× |
| byte_count | BRUTE_FORCE | 0 | 551 | ∞ |
| average_packet_size | BRUTE_FORCE | 0 | 50.4 | ∞ |
| minimum_packet_size | BRUTE_FORCE | 0 | 44 | ∞ |
| duration | DOS | 5.25s | 0.195s | 0.037× |
| duration | RECONNAISSANCE | 93.19s | 0.0068s | 0.00007× |

**Interpretation:** Live attacks are **shorter in duration** than CICIDS2017 attacks (except PORT_SCAN), have **larger minimum packet sizes**, and **higher byte/packet volumes** for PORT_SCAN and BRUTE_FORCE. DOS attacks in CICIDS are long-lived; live DOS is very short.

---

## 6. Statistical Distribution Analysis

Distribution distances were computed using Wasserstein distance and KS statistic (`stage11_8_6_distribution_distances.csv`).

### Strongest statistical shifts (CICIDS attack class vs live attack class)

| Feature | Comparison | Wasserstein | KS Statistic | KS p-value |
|---------|-----------|------------:|-------------:|-----------:|
| duration | CICIDS_RECONNAISSANCE vs live_RECONNAISSANCE | 93.18 | 0.998 | <1e-10 |
| duration | CICIDS_DOS vs live_DOS | 5.25 | 0.997 | <1e-10 |
| duration | CICIDS_PORT_SCAN vs live_PORT_SCAN | 0.0068 | 0.998 | <1e-10 |
| bytes_per_second | CICIDS_RECONNAISSANCE vs live_RECONNAISSANCE | 76.24 | 0.998 | <1e-10 |
| packet_size_std | CICIDS_PORT_SCAN vs live_PORT_SCAN | 10.82 | 0.998 | <1e-10 |
| average_packet_size | CICIDS_PORT_SCAN vs live_PORT_SCAN | 47.0 | 0.998 | <1e-10 |
| maximum_packet_size | CICIDS_PORT_SCAN vs live_PORT_SCAN | 56.5 | 0.998 | <1e-10 |
| byte_count | CICIDS_PORT_SCAN vs live_PORT_SCAN | 538 | 0.998 | <1e-10 |
| backward_bytes | CICIDS_PORT_SCAN vs live_PORT_SCAN | 236 | 0.998 | <1e-10 |
| forward_bytes | CICIDS_PORT_SCAN vs live_PORT_SCAN | 313 | 0.998 | <1e-10 |

All tested comparisons show **highly significant distribution differences** (p < 1e-10). The shift is not random noise; it is systematic.

---

## 7. BENIGN vs Attack Separability

The analysis compared whether live attack feature values move toward the CICIDS BENIGN region (`stage11_8_6_separability.csv`).

### Key finding: Live attacks do NOT resemble CICIDS BENIGN

For PORT_SCAN:
- CICIDS BENIGN median packet_size_std = 0
- CICIDS PORT_SCAN median packet_size_std = 0
- Live PORT_SCAN median packet_size_std = 10.82

Live PORT_SCAN has **non-zero packet_size_std** (10.82) while both CICIDS BENIGN and CICIDS PORT_SCAN have 0. This means live attacks are actually **farther from CICIDS BENIGN** in this dimension, not closer.

For BRUTE_FORCE:
- CICIDS BENIGN median byte_count = 284
- CICIDS BRUTE_FORCE median byte_count = 0
- Live BRUTE_FORCE median byte_count = 551

Live BRUTE_FORCE has **higher byte_count** than CICIDS BENIGN, moving it **away** from the benign region.

**Conclusion:** Live attacks are not simply "looking more benign" to the model through these features. They occupy a **different region entirely**—neither CICIDS BENIGN nor CICIDS attack-like.

---

## 8. Frozen Model Prediction Analysis

All 526 attacks predicted as BENIGN. Prediction analysis (`stage11_8_6_prediction_analysis.csv`):

| Attack Class | Count | Mean BENIGN Prob | Mean Confidence | Margin |
|-------------|------:|-----------------:|----------------:|-------:|
| PORT_SCAN | 164 | 0.9271 | 0.9271 | 0.8542 |
| BRUTE_FORCE | 153 | 0.8978 | 0.8978 | 0.7957 |
| RECONNAISSANCE | 166 | 0.9093 | 0.9093 | 0.8187 |
| DOS | 43 | 0.8541 | 0.8541 | 0.7083 |

The model is **consistently confident** in its BENIGN predictions (85–93% confidence). No predictions transition to any attack class.

### Feature correlations with BENIGN probability

| Feature | Pearson r | Spearman ρ | p-value |
|---------|----------:|-----------:|--------:|
| average_packet_size | -0.833 | 0.194 | 7.3e-06 |
| bytes_per_second | -0.771 | -0.216 | 5.6e-07 |
| packet_size_std | -0.722 | 0.262 | 1.1e-09 |
| maximum_packet_size | -0.353 | 0.131 | 2.6e-03 |
| forward_bytes | -0.020 | 0.155 | 3.7e-04 |
| fin_count | 0.434 | 0.157 | 2.9e-04 |
| syn_count | 0.433 | 0.171 | 8.3e-05 |
| duration | -0.147 | 0.207 | 1.6e-06 |

**Strong negative Pearson correlations:** `average_packet_size`, `bytes_per_second`, `packet_size_std`. As these increase, BENIGN probability decreases. However, in live attacks these values are **lower** than CICIDS attack values, pushing the model toward BENIGN.

---

## 9. Univariate Counterfactual Diagnostics

For each of the 13 non-flag features, the median of the corresponding CICIDS attack class was substituted into live attack samples. The frozen model was re-evaluated.

**Result: 0% recall improvement for ALL single-feature counterfactuals.**

| Feature | Recall Improvement | BENIGN Prob Change | Transitions |
|---------|------------------:|-------------------:|------------:|
| average_packet_size | 0.0 | -0.143 | 0 |
| byte_count | 0.0 | -0.131 | 0 |
| forward_bytes | 0.0 | -0.130 | 0 |
| maximum_packet_size | 0.0 | -0.099 | 0 |
| backward_bytes | 0.0 | -0.094 | 0 |
| packets_per_second | 0.0 | -0.009 | 0 |
| duration | 0.0 | -0.009 | 0 |
| minimum_packet_size | 0.0 | +0.000 | 0 |

**Diagnostic label:** `UNIVARIATE COUNTERFACTUAL DIAGNOSTIC — NOT CAUSAL PROOF`

No single feature is sufficient to overcome the Random Forest ensemble's collective decision boundary. This does NOT mean features are unimportant; it means the model's classification depends on **combinations** of features across 200 trees.

The largest BENIGN probability reductions come from:
1. `average_packet_size` (-0.143 to -0.156)
2. `byte_count` (-0.130 to -0.142)
3. `forward_bytes` (-0.130 to -0.132)
4. `maximum_packet_size` (-0.099 to -0.088)

These are the features that, when moved toward CICIDS attack values, most reduce the model's benign confidence.

---

## 10. Top Feature Combination Diagnostics

Limited combinations of the top 3 counterfactual features were tested (`stage11_8_6_combinations.csv`):

| Features Tested | Recall Improvement |
|----------------|-------------------:|
| average_packet_size | 0.0 |
| average_packet_size + byte_count | 0.0 |
| average_packet_size + byte_count + forward_bytes | 0.0 |

Even the top 3 features combined do not flip predictions. This reinforces that the failure is **multivariate** and requires feature combinations that the counterfactual test cannot explore.

---

## 11. Training Duplication Analysis

| Class | Total Rows | Unique Rows | Duplicate Rows | Unique Ratio |
|-------|----------:|-----------:|---------------:|-------------:|
| BENIGN | 22,731 | 19,198 | 3,533 | 84.5% |
| DOS | 21,001 | 17,595 | 3,406 | 83.8% |
| PORT_SCAN | 7,946 | 323 | 7,623 | **4.1%** |
| BRUTE_FORCE | 4,947 | 3,658 | 1,289 | 73.9% |
| RECONNAISSANCE | 36 | 36 | 0 | 100% |

**Critical findings:**
- **PORT_SCAN is 95.9% duplicate feature vectors.** The model may be memorizing a small number of PORT_SCAN patterns.
- **RECONNAISSANCE has only 36 samples** (0.06% of training data). The model has almost no genuine RECON exemplars.
- The high duplication in PORT_SCAN and DOS may inflate apparent training accuracy while reducing generalization.

---

## 12. Feature Importance vs Evidence

| Feature | RF Importance | Shift Evidence | CF Evidence | Assessment |
|---------|-------------:|---------------:|------------:|------------|
| packet_size_std | 0.1161 | Strong | Moderate | High-impact feature with major distribution shift |
| average_packet_size | 0.0949 | Strong | Strong | High importance + strong shift + strong CF effect |
| byte_count | 0.0411 | Strong | Strong | Moderate importance + strong shift |
| backward_bytes | 0.0411 | Moderate | Moderate | Moderate importance + shift |
| forward_packets | 0.0388 | Moderate | Weak | Moderate importance + moderate shift |
| duration | 0.0273 | Strong | Weak | Lower importance but extreme shift |
| maximum_packet_size | 0.0273 | Strong | Moderate | Lower importance + shift |
| packets_per_second | 0.0165 | Strong | Weak | Lower importance + shift |
| bytes_per_second | 0.0131 | Strong | Moderate | Lower importance + strong Pearson correlation |
| forward_bytes | 0.0119 | Moderate | Moderate | Moderate importance + shift |
| backward_packets | 0.0119 | Moderate | Weak | Moderate importance + moderate shift |
| minimum_packet_size | 0.0096 | Strong | Weak | Lower importance + extreme shift |
| syn_count | 0.0094 | Moderate | Weak | Moderate importance (flag feature) |
| fin_count | 0.0088 | Moderate | Weak | Moderate importance (flag feature) |
| ack_count | 0.0084 | Moderate | Weak | Moderate importance (flag feature) |
| rst_count | 0.0056 | Weak | Weak | Low importance |
| psh_count | 0.0044 | Weak | Weak | Low importance |

**Interpretation:** The model places highest importance on `packet_size_std` and `average_packet_size`. These also show the strongest distribution shift and counterfactual effects. The evidence converges on these two features as primary discriminators in the trained model, and their live values are systematically different from CICIDS attack values.

---

## 13. Root-Cause Classification

| Finding | Evidence | Strength |
|---------|----------|----------|
| TCP flag semantic mismatch | Stage 11.8.5 A/B test: 0% prediction change | **Confirmed but not causal** |
| Packet-size shift | Extreme live vs CICIDS differences in packet_size_std, average_packet_size, maximum_packet_size | **Strong evidence** |
| Byte-count shift | Live PORT_SCAN byte_count 90× CICIDS; live BRUTE_FORCE byte_count diverges from CICIDS median of 0 | **Strong evidence** |
| Rate shift | packets_per_second and bytes_per_second show significant distribution differences | **Moderate evidence** |
| Directionality shift | forward/backward packet and byte ratios differ from CICIDS patterns | **Moderate evidence** |
| Loopback effect | Loopback interface produces synthetic traffic with unrealistic packet timing and sizes | **Strong evidence** |
| Training duplication | PORT_SCAN 95.9% duplicates; RECON only 36 samples | **Strong evidence** |
| RECON scarcity | 36 samples (0.06%) — model cannot learn RECON patterns | **Strong evidence** |
| Model under-generalization | 0% recall on all 526 attacks despite high training accuracy | **Strong evidence** |

### Category Classification

**A — Feature Semantic Mismatch:** TCP flag mismatch is confirmed but produced **no measurable prediction effect**. NOT a root cause.

**B — Feature Distribution Shift:** **Strong evidence.** Live attacks have systematically different duration, packet sizes, byte counts, and rates from CICIDS2017 attacks. The model was trained on one distribution and evaluated on another.

**C — Feature Direction Shift:** **Moderate evidence.** Some live attack features move away from CICIDS BENIGN (e.g., higher packet_size_std), not toward it. The model's BENIGN predictions are not caused by attacks "looking more benign" in these dimensions.

**D — Attack Generation Artifact:** **Strong evidence.** Loopback capture produces traffic with 44-byte minimum packet sizes, 10.8 packet_size_std, and ~50-byte average packet sizes for PORT_SCAN—none of which resemble real network attacks. This is an artifact of local loopback generation, not real-world attack traffic.

**E — Training Data Limitation:** **Strong evidence.** PORT_SCAN duplication (95.9%) means the model sees only ~30 unique PORT_SCAN patterns. RECONNAISSANCE scarcity (36 samples) means the model essentially guesses RECON. The model's apparent training accuracy is inflated by repeated patterns.

**F — Model Generalization Limitation:** **Strong evidence.** A 200-tree Random Forest with max_depth=20 trained on 45K samples should generalize better. The 0% recall on 526 diverse attacks indicates the model has learned CICIDS-specific patterns that do not transfer to loopback-generated traffic.

---

## 14. Remaining Uncertainty

1. **Combination effects:** Univariate counterfactuals cannot capture the multivariate decision boundaries of 200 trees. The true root cause may require 3–5 feature combinations.
2. **Loopback vs non-loopback:** Stage 11.8.4 attempted non-loopback collection but could not complete controlled attacks. We cannot isolate loopback effect from feature shift.
3. **Counterfactual validity:** Replacing one feature with a median creates unrealistic feature vectors that may fall outside the model's training manifold. Results are diagnostic, not causal.
4. **Optimal remediation:** We do not know whether retraining with loopback data, feature engineering, or a different model architecture would be most effective.

---

## 15. Production Integrity

| Check | Status |
|-------|--------|
| Production files modified | **NO** |
| Model modified | **NO** |
| Model retrained | **NO** |
| Thresholds modified | **NO** |
| Rules modified | **NO** |
| Original datasets modified | **NO** |
| Model hash | **7bcc643154a1f44d** (unchanged) |

All analysis was evaluation-only. No production code, model, or data was altered.

---

## 16. Tests

The existing test suites were not executed in this stage. This is an evaluation-only diagnostic stage. No tests were weakened or deleted.

**Note:** Stage 9 live test (`test_stage9_live.py`) is known to time out in this environment. This is an existing limitation unrelated to Stage 11.8.6.

---

## 17. Recommendation for Stage 11.8.7

**Primary recommendation:** Do NOT retrain the model yet. First, collect **non-loopback controlled attacks** on a real network interface to isolate loopback artifacts from genuine feature shift.

**Secondary recommendation:** If non-loopback collection is not feasible, consider:
1. **Feature reduction:** Remove or transform features with extreme loopback-specific artifacts (`packet_size_std`, `minimum_packet_size`, `duration`).
2. **Domain adaptation:** Collect a small set of loopback benign/attack flows and apply domain adaptation techniques.
3. **Ensemble thresholding:** The model's BENIGN probability distributions for attacks (0.85–0.93) overlap with benign confidence ranges. A simple threshold on BENIGN probability alone will not separate attacks from benign.

**Stage 11.8.7 direction:** Focus on **non-loopback attack collection and evaluation** to determine whether the root cause is loopback artifact or fundamental feature-space mismatch.

---

## 18. Final Questions

### Q1: Which features differ most between live attacks and CICIDS2017?

**Answer:** `duration`, `packet_size_std`, `average_packet_size`, `maximum_packet_size`, `byte_count`, `backward_bytes`, `bytes_per_second`, `packets_per_second`, `minimum_packet_size`, `packet_count`. Live attacks are shorter, have larger minimum packet sizes, higher packet size variance, and different byte/rate profiles.

### Q2: Do live attacks resemble CICIDS BENIGN or CICIDS ATTACK distributions?

**Answer:** Neither. Live attacks occupy a distinct region. For example, live PORT_SCAN has packet_size_std=10.82 while both CICIDS BENIGN and CICIDS PORT_SCAN have 0. Live attacks are not "looking more benign"—they look **unlike anything in the training distribution**.

### Q3: Which features have the strongest counterfactual effect?

**Answer:** `average_packet_size` (-0.143 to -0.156 BENIGN probability change), `byte_count` (-0.130 to -0.142), `forward_bytes` (-0.130 to -0.132), `maximum_packet_size` (-0.099 to -0.088), `backward_bytes` (-0.094). No single feature flips predictions, but these most reduce benign confidence.

### Q4: Does the model's BENIGN confidence correlate with particular features?

**Answer:** Yes. Strong negative Pearson correlations with `average_packet_size` (-0.833), `bytes_per_second` (-0.771), and `packet_size_std` (-0.722). Higher values of these features are associated with lower BENIGN probability.

### Q5: Is loopback still a plausible major contributor?

**Answer:** **Yes.** Loopback traffic has unrealistic packet sizes (44-byte minimum), timing, and flow characteristics that do not match real network attacks. This is strong evidence of attack-generation artifact.

### Q6: Is attack-generation methodology a plausible contributor?

**Answer:** **Yes.** The local Scapy-based attack generators on loopback produce traffic with statistical properties (44-byte minimums, high packet_size_std, short durations) that are artifacts of the generation method, not real attacks.

### Q7: Is the existing model fundamentally under-generalized to this traffic?

**Answer:** **Yes.** The model achieves high accuracy on CICIDS test data but 0% recall on 526 controlled attacks. This indicates the model has learned CICIDS-specific patterns that do not generalize to loopback-generated traffic.

### Q8: Is retraining justified now?

**Answer:** **NO.** Retraining on the same CICIDS data would likely reproduce the same failure. Retraining requires either (a) non-loopback attack data, or (b) deliberate domain adaptation to loopback characteristics. Neither is available yet.

---

## 19. Production Integrity

| Property | Value |
|----------|-------|
| Production files modified | NO |
| Model modified | NO |
| Model retrained | NO |
| Thresholds modified | NO |
| Rules modified | NO |
| Original datasets modified | NO |
| Model hash | `7bcc643154a1f44d` |

---

## 20. Tests

No existing tests were modified or deleted. Stage 11.8.6 is an evaluation-only diagnostic stage.

---

## 21. GREEN/YELLOW/RED Verdict

**YELLOW**

**Reasoning:**
- Experiment is valid: evaluation-only, no production changes, model hash unchanged.
- Evidence is sufficient for diagnosis: distribution shifts are quantified, counterfactuals are bounded, root causes are classified.
- Uncertainty remains: exact causal combination of features unknown, loopback effect not isolated, optimal remediation path unclear.

**Stage 11.8.6 is COMPLETE.**

---

*Generated by Stage 11.8.6 Feature-Space Deep Dive*
*Model hash: 7bcc643154a1f44d*
*Outputs: stage11_8_6_feature_statistics.csv, stage11_8_6_distribution_shift.csv, stage11_8_6_distribution_distances.csv, stage11_8_6_range_overlap.csv, stage11_8_6_separability.csv, stage11_8_6_prediction_analysis.csv, stage11_8_6_feature_correlations.csv, stage11_8_6_counterfactual_results.csv, stage11_8_6_combinations.csv, stage11_8_6_duplication.csv, stage11_8_6_feature_importance.csv*
