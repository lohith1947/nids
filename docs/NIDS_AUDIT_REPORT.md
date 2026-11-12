# NIDS Code Audit Report

**Audit date:** 2026-09-12
**Audited project:** `NIDS` (Network Intrusion Detection System) — Python 3.12, Scapy + scikit-learn + Streamlit
**Audit mode:** Read-only. No project source file was modified. This report is the only file written.

---

## 1. Executive summary

The project is a well-structured, flow-based NIDS with a clean five-stage pipeline:

```
Scapy capture ──▶ FlowManager ──▶ RuleEngine ──┐
                  (5-tuple flows)              ├─▶ CorrelationEngine ──▶ RiskScorer ──▶ AlertManager ──▶ Streamlit dashboard
                                              └─▶ ML model (RandomForest+Scaler) ─┘                  ("NIDS Sentinel")
```

- **Every unit test suite I ran passes** (alerts, rule_engine, risk_scorer, correlator, pipeline, concurrency, dashboard, regression, evaluation, stage10, attribution, collector 11.8.7). One test in `test_stage11_8_7_split` fails (33/34) — a test bug, not a production bug (see §5.4).
- **Three real code defects confirmed by execution**, none of which cause crashes but all affect correctness:
  - **P1 — FlowManager timeout is not an inactivity timeout** (`flow_manager.py`): a flow is force-closed 10 s after *creation* even if it is continuously active. Long-lived connections get split into multiple fragmented flows.
  - **P2 — ML class-label mapping is fragile** (`model.py` + `correlator.py`): depends on the trained classifier containing *all five classes in integer order 0..4*. If any leading class is absent from training, labels + top-3 probabilities are silently mislabelled (verified).
  - **P2 — Alert dedup overwrites the stored confidence** with `RiskResult.confidence` instead of preserving the combined confidence, plus dead code (`alerts.py:259-265`).
- Quality strengths: excellent documentation-with-rationale in code, strong test coverage, thread-safety of the alert store and worker guarded carefully, real error-isolation in the pipeline, an unusually rigorous Stage 11 evaluation harness (session-level splits, attribution audit, non-loopback validation).

---

## 2. Architecture and how it works

| Stage | File | Responsibility |
|---|---|---|
| Config | `config.py` | Central thresholds (`FlowConfig`, `RuleConfig`), `SEVERITY_MAP`. **Thresholds are explicitly marked "initial / not calibrated".** |
| Capture | `packet_capture.py` | Scapy `sniff()` wrapper; `parse_packet_info()` extracts 5-tuple, flags, size. **IPv4-only** (`if IP not in packet`). |
| Flow model | `flow.py` | Bidirectional `Flow`: per-direction packet/byte counts, TCP flag counters (SYN/ACK/FIN/RST/PSH), duration, and the 18-feature vector via `get_features()`. |
| Flow tracking | `flow_manager.py` | Canonical 5-tuple key (both directions → one flow); heap-based expiration; returns completed flows. **See P1 bug.** |
| Features | `features.py` | Canonical 18-feature schema + TCP flag bit-masks (single source of truth for the ML side). |
| Rule engine | `rule_engine.py` | Threshold rules: DOS (pps/bps/SYN-ratio), PORT_SCAN (unique ports+S collaborative cross-flow window), BRUTE_FORCE (repeated short auth attempts), RECONNAISSANCE (multi-host scan), with loopback false-positive suppression. Emits `RuleResult(rule_prediction, rule_confidence, triggered_rules)`. |
| ML | `model.py` | `NIDSModel` = `StandardScaler` + `RandomForestClassifier`. Training via `train_model.py` on a CICIDS2017 sample, saved to `models/nids_model.joblib`. **See P2 bug.** |
| Fusion | `correlator.py` | `CorrelationEngine.correlate()` fuses rule + ML into `DetectionResult` using documented cases (agree → probability union; disagree → higher-confidence × 0.85; one-side-only → × 0.80; both benign → min). |
| Risk | `risk_scorer.py` | Maps prediction + confidence to a 0–100 risk score within per-class `[base, ceiling]` ranges and a severity. |
| Alerts | `alerts.py` | `AlertManager`: dedup (5-tuple + attack type within 30 s window), per-source rate limiting, severity filter, thread-safe in-memory store; `Alert` carries rule/ml confidences, feature snapshot, top-3. **See P3 bug.** |
| Orchestrator | `pipeline.py` | `NIDSPipeline` (per-flow processing with per-stage error isolation + failure counter), `ProcessingWorker` (background thread draining a packet queue), stats, graceful shutdown/finalization, dashboard integration. |
| Dashboard | `dashboard.py`, `dashboard_data.py`, `dashboard_components.py` | Streamlit UI; pure aggregation in `dashboard_data.py` (KPIs, time series, agreement matrix, top sources), UI rendering in `dashboard_components.py`. |
| Training | `data_extractor.py`, `train_model.py` | CICIDS2017 sample → 18-feature csv, `CLASS_LABELS = [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE]`, trains and saves the joblib bundle. |
| Evaluation | `evaluation/` | Full Stage 11 harness: `schema.py`, `validation.py`, `splitting.py` (session-level temporal/KFold/LOSO splits — avoids leakage), 10+ collectors/generators, dozens of reports and JSONL datasets in `evaluation/datasets/`. |

---

## 3. Verdict on the three leading candidate bugs

### P1 — `flow_manager.py`: expiration is creation-time-based, not inactivity-based  (HIGH)

`process_packet()` schedules expiry **only when the flow is first created**:

```
flow_manager.py:155   expiry_time = timestamp + self.flow_timeout
flow_manager.py:156   heapq.heappush(self._expiry_heap, (expiry_time, key))
```

It is **never refreshed** as packets arrive (line 162 calls `flow.add_packet(...)` but no heap update). `_check_timeouts()` therefore closes any flow whose *first-packet* time exceeds `flow_timeout`, regardless of activity.

The docstring/design say the timeout is *inactivity-based* ("Close and return any flows that have been inactive longer than `self.flow_timeout`"; `config.py` FlowConfig: "Seconds of inactivity before a flow is considered closed").

**Verified by execution** (flow_timeout=10):

```
t= 0 : flow created
t= 2,4,6,8 : active=1 (packets still arriving every 2 s)
t=10 : active=0  completed=1   <-- flow force-closed despite 2 s inactivity
t=12 : active=1  (a brand-new flow object for the same connection)
```

**Impact:** For any connection lasting >10 s, the connection is split into multiple small flows. Each fragment is separately scored/detected and separately deduped → under-counted features, degraded detection of slow/long attacks, inflated flow counts, fragmented alert attribution.

**Fix:** push a fresh `(timestamp + flow_timeout, key)` entry on **every** packet and lazily skip stale entries in `_check_timeouts` (or store `last_packet_ts` per flow and only close when `now - last_packet_ts >= timeout`).

---

### P2 — `model.py` / `correlator.py`: class-label mapping assumes all 5 classes present & int-ordered  (MEDIUM–HIGH, latent)

- `model.classes_` (property, `model.py:58-60`) returns the **constant** `CLASS_LABELS`, not `self.clf.classes_`.
- `predict()` (`model.py:115-119`) maps predictions by searching `clf.classes_` and indexing the **constant** `CLASS_LABELS`:
  `pred_indices = clf.classes_.searchsorted(clf.predict(...))` then `CLASS_LABELS[i]`.
  This is only correct if `clf.classes_ == [0,1,2,3,4]`, i.e. every class present and integer labels 0..4.
- `correlator._get_ml_prediction()` (`correlator.py:305`) zips `self.model.classes_` (constant) against `predict_proba` columns (ordered by `clf.classes_`) — same assumption.

**Verified by execution:** a model trained *without* class 0 (BENIGN) — `clf.classes_ = [1,2,3,4]` — produced `'BENIGN'` predictions that should have been attacks (silent mislabelling).

**Current shipped model is safe** — `nids_model.joblib` contains all five classes in order 0..4 (verified at load). So this is a robustness/latent defect, not an active mislabelling bug right now. But any re-training on a class-imbalanced subset (frequent in practice) will silently corrupt labels + top-3.

**Fix:** build an explicit `int_label → CLASS_LABELS[str]` map from `clf.classes_` in `load()/train()`; validate all five classes present before accepting a model (warn/raise otherwise); index label names from `classes_` positions, not from integer values.

---

### P3 — `alerts.py`: dedup path overwrites combined confidence with a different quantity + dead code  (MEDIUM)

`create_alert()` dedup branch, `alerts.py:259-265`:

```python
existing_alert.confidence = max(
    existing_alert.confidence,
    risk_result.risk_score / 100.0 if ... else existing_alert.confidence   # <-- computed then discarded
)
existing_alert.confidence = risk_result.confidence if hasattr(risk_result, 'confidence') else ...  # <-- overwrites
```

**Verified by execution:**

```
First alert:   confidence = 0.850   (combined confidence — correct)
After dedup:   confidence = 0.970   (= RiskResult.confidence, a fixed 0.97; the new combined 0.60 was ignored)
```

Two problems:
1. Lines 259–263 are pure dead code (result immediately overwritten).
2. Line 265 replaces the documented "confidence = combined confidence" semantics with `RiskResult.confidence` (a different quantity). Re-aggregated alerts therefore display a confidence that does not match their `rule_confidence`/`ml_confidence`/`combined` story. `RiskResult.confidence` is only meaningfully used at creation time in `_build_alert` via `detection_result.combined_confidence`; the dedup path should receive the *new* `combined_confidence` (or keep `max(...)` of combined confidences) to stay consistent.

---

## 4. Other findings (lower severity)

| # | Location | Finding |
|---|---|---|
| 4.1 | `flow_manager.py:18-22` | Known & documented limitation: timeout checks only fire on packet arrival; a dead network with silent traffic never expires flows. Consider a background expiry thread. |
| 4.2 | `packet_capture.py:69` | IPv4 only — `if IP not in packet: return None`. Any IPv6 traffic is silently dropped by the whole system. |
| 4.3 | `packet_capture.py:50-56` | `capture_packets` is blocking; `stop_callback` is passed straight through as Scapy's `stop_filter`, which Scapy calls **with the packet argument**. A 0-arg lambda (`lambda: ...`) raises `TypeError` and the capture thread dies. The repo's own test history (`test_live_e2e` vs the "corrected" variants) shows this was a real, previously-hit footgun. Hard-code `stop_filter=lambda pkt: stop_callback()` or mandate a 1-arg callback. |
| 4.4 | `alerts.py:280` | Rate-limit reset in "discard" mode is a no-op: `self._rate_limit_state[source_ip] = self._rate_limit_state[source_ip]`. Harmless but pointless. |
| 4.5 | `alerts.py:422-438` | `_find_alert_by_key` is O(n) over all alerts on every dedup hit; fine now, will be a hot spot at scale. Use a `dedup_key → alert_id` dict. |
| 4.6 | `config.py` | All detection thresholds are explicitly "initial, not calibrated". While the rule-engine unit tests confirm self-consistency, detection quality versus *real* Kali traffic on 192.168.56.x should be recalibrated before trusting them (the Stage-11 reports in `evaluation/datasets/` already document FP/attribution issues this surfaced). |
| 4.7 | alerts store | In-memory only. `prune_old_dedup_state()` exists but is not called anywhere by the pipeline — `_dedup_state`/`_rate_limit_state` grow until `clear_alerts()` or process exit. |
| 4.8 | `RuleEngine` cross-flow windows | Port-scan / brute-force / recon use time-windowed cross-flow state; per `test_rule_engine` the loopback-suppression works. State is never explicitly pruned on a timer (analogous to 4.7). |

---

## 5. Test-suite status (ran them all)

| Suite | Result |
|---|---|
| `test_alerts`, `test_rule_engine`, `test_risk_scorer`, `test_correlator` | ALL PASS |
| `test_pipeline`, `test_concurrency`, `test_regression`, `test_dashboard` | ALL PASS |
| `test_evaluation` | 24/24 PASS |
| `test_stage10`, `test_attribution_regression` | ALL PASS |
| `test_collector_11_8_7` | 17/17 PASS |
| `test_stage11_8_7_split` | **33/34 — 1 FAIL** (see 5.1) |
| `test_stage9_live`, `test_phase1_smoke`, `test_live_e2e*` | **NOT RUN** — live-capture suites need admin privileges + a loopback interface and take minutes; matters flagged for P2/P1 would not be caught by them anyway. |

### 5.1 The one failing test (test bug, not product bug)

`TestGeneratorDecoupling.test_full_mode_still_initializes_pipeline` FAILS:
`<module 'NIDS.evaluation.collect_attack_11_8_v2'> does not have the attribute 'NIDSModel'`.

The Stage 11.8.7 refactor intentionally moved all NIDS.* imports behind lazy/`None` initialization in generator mode, so the module no longer exposes `NIDSModel` / `RuleEngine` / etc. as import-time attributes. The test patches the wrong target. **Fix the test** — patch at the location where the module *actually* imports them (e.g. patch `NIDS.model.NIDSModel` and assert the collector instantiates it), not `collect_attack_11_8_v2.NIDSModel`.

### 5.2 Noise in the same file

`TestServerReadiness` bind-failure tests pass but the failing bind (port 99999) raises an uncaught `OverflowError` in the thread → `Exception in thread ... ` traceback noise. Catch/`sys.excepthook` the expected failure inside `tcp_server_thread`/`udp_server_thread` (the `ready_event` is already set in `finally`).

### 5.3 Side effect worth knowing

`TestGeneratorDecoupling.test_generator_mode_run_generators_only_returns_empty_dataset` actually **ran the real attack generators** (PORT_SCAN, BRUTE_FORCE, DOS-UDP, RECONNAISSANCE) for ~18 s toward `192.168.56.107` during the test run (records are discarded, hence the pass). It is a functional check, but it puts genuine attack traffic on whichever network that IP resolves to — keep this suite away from production interfaces.

---

## 6. Recommended fixes, priority order

1. **P1 — FlowManager inactivity expiry.** Refresh the heap entry on every packet (lazy-delete stale entries) so `_check_timeouts` uses last-activity time. Remove the misleading "inactive" wording from the docstring if an absolute timeout is actually intended.
2. **P2 — Robust label mapping.** In `NIDSModel.load()`/`train()`: build `{int_label: name}` from `clf.classes_`; verify all 5 classes present (raise a clear error otherwise); derive label names and probabilities from the same mapping. Have `CorrelationEngine._get_ml_prediction` use that mapping for `top3`.
3. **P3 — Dedup confidence.** Replace dead lines 259–263; in the dedup branch set `existing_alert.confidence` to the new `detection_result.combined_confidence` (or `max` it) so it stays the "combined" quantity shown everywhere else.
4. **Test fixes:** repoint the two `test_stage11_8_7_split` problems (§5.1, §5.2); consider adding a unit test that reproduces the P1 expiry behaviour so #1 can't regress.
5. **Calibrate thresholds** (`config.py`) against the real lab dataset — the Stage-11 reports are already the evidence base for this.
6. **Robustness:** background flow-expiry thread (removes the documented limitation); IPv6 stack in `parse_packet_info`; `stop_filter` wrapper in `capture_packets`; wire `prune_old_dedup_state` into a periodic loop; dict-index the dedup lookup; drop the no-op rate-limit reset at `alerts.py:280`.

---

## 7. What I did not touch

- Nothing in `NIDS/` or `NIDS/evaluation/` was modified (read-only audit).
- Live capture test suites were intentionally not executed (privileges + duration); a small standalone script confirmed bugs P1, P2, P3 and was run from the OS temp directory, leaving the project untouched.
- `cloud security_project.txt` and `STAGE_10_PHASE2_AUDIT.md` (in the parent folder) are outside the audited package and were not modified.