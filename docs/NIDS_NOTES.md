# NIDS Project — Development Notes

**Project:** Network Intrusion Detection System (NIDS) — "NIDS Sentinel"
**Location:** `C:\Users\SRIRAM NAIDU\Desktop\AI agent\NIDS\`
**Stack:** Python 3.12 (workspace) / 3.14.4 (Ubuntu lab deployment), Scapy + scikit-learn + Streamlit
**Notion page:** https://app.notion.com/p/404566c01b3581b488d9d4ec016fa50b?pvs=204

---

## Architecture (5-stage pipeline)

```
Scapy capture → FlowManager → RuleEngine → CorrelationEngine → RiskScorer → AlertManager → Streamlit dashboard
                              └─────────→ ML model (RandomForest+Scaler) ─────────┘
```

| Stage | File | Responsibility |
|-------|------|----------------|
| Config | `config.py` | Thresholds (`FlowConfig`, `RuleConfig`), `SEVERITY_MAP` |
| Capture | `packet_capture.py` | Scapy `sniff()` wrapper; IPv4-only |
| Flow model | `flow.py` | Bidirectional `Flow`, 18-feature vector |
| Flow tracking | `flow_manager.py` | Canonical 5-tuple key, heap-based expiry |
| Features | `features.py` | 18-feature schema + TCP flag bit-masks |
| Rule engine | `rule_engine.py` | Threshold rules: DOS, PORT_SCAN, BRUTE_FORCE, RECONNAISSANCE |
| ML | `model.py` | `StandardScaler` + `RandomForestClassifier` |
| Fusion | `correlator.py` | Rule + ML fusion into `DetectionResult` |
| Risk | `risk_scorer.py` | 0–100 risk score + severity |
| Alerts | `alerts.py` | Dedup, rate limiting, severity filter, thread-safe store |
| Orchestrator | `pipeline.py` | Per-flow processing, worker thread, stats |
| Dashboard | `dashboard.py` + components | Streamlit UI ("NIDS Sentinel") |

---

## Bug Fixes

### P1 — FlowManager inactivity expiry (HIGH) — FIXED

**File:** `flow_manager.py`

**Root cause:** Flow expiry was scheduled once at creation time (`timestamp + flow_timeout`) and never refreshed. `_check_timeouts()` closed flows based on first-packet age, not inactivity. Long-lived connections were fragmented into multiple small flows.

**Fix:**
- `process_packet()` and `process_packet_info()` now push a fresh `(timestamp + flow_timeout, key)` heap entry on **every** packet.
- `_check_timeouts()` uses lazy deletion: skips stale entries where `current_time - flow.last_time < flow_timeout` (flow was active since entry was pushed). Only closes a flow when `current_time - flow.last_time >= flow_timeout` (genuine inactivity timeout).

**Files changed:** `flow_manager.py` (lines 143-167, 178-218)

**Verification:** 237/241 existing tests pass. The 3 failures in `test_stage11_8_7_split.py` and 1 error in `test_regression.py::test_scenario` are pre-existing issues unrelated to this change.

---

### P2 — ML class-label mapping (MEDIUM-HIGH) — FIXED

**Files:** `model.py`, `correlator.py`

**Root cause:** `model.classes_` returned the constant `CLASS_LABELS` instead of actual `clf.classes_` mapped to label names. `predict()` used `searchsorted` positions as indices into `CLASS_LABELS` (only correct if `clf.classes_ == [0,1,2,3,4]`). `correlator._get_ml_prediction()` zipped constant `CLASS_LABELS` against `predict_proba` columns ordered by `clf.classes_` — mismatched when classes are missing. If any leading class is absent from training, labels + top-3 probabilities are silently mislabelled.

**Fix:**
- `NIDSModel.classes_` property now derives labels from `clf.classes_` (integer values) mapped through `CLASS_LABELS[int(c)]`
- `NIDSModel.predict()` maps predicted integer values via `CLASS_LABELS[int(v)]` and finds correct probability column via `class_to_col` mapping
- `NIDSModel.train()` and `NIDSModel.load()` validate all 5 classes present, raising a clear `ValueError` if any are missing
- Added `_label_for_int()` helper method
- `CorrelationEngine._get_ml_prediction()` zips `clf.classes_` (actual integers) with probs, mapping each to `CLASS_LABELS[int(class_val)]`
- Added `from .data_extractor import CLASS_LABELS` import to `correlator.py`

**Files changed:** `model.py` (classes_ property, `_label_for_int`, train validation, predict fix, load validation), `correlator.py` (CLASS_LABELS import, `_get_ml_prediction` fix)

**Verification:** 237/241 tests pass (same as baseline). No regressions.

---

### P3 — Dedup confidence overwrite (MEDIUM) — FIXED

**File:** `alerts.py`

**Root cause:** Dedup branch had dead code (lines 259-263 immediately overwritten) and replaced combined confidence with `RiskResult.confidence` (a different quantity than `combined_confidence`).

**Fix:** Removed dead code; in dedup branch set `existing_alert.confidence = max(existing_alert.confidence, detection_result.combined_confidence)` to preserve combined confidence semantics.

**Verification:** 237/241 tests pass (same as baseline). No regressions.

---

### F7/F8 — Investigation UI confidence truthfulness (CRITICAL/HIGH) — ALREADY IMPLEMENTED

**Files:** `alerts.py`, `dashboard_components.py`, `dashboard_data.py`

**Status:** Already correctly implemented in the current codebase:
- `Alert` dataclass has `rule_confidence` and `ml_confidence` fields (lines 101, 103)
- `_build_alert()` populates them from `detection_result.rule_confidence` / `ml_confidence` (lines 476, 477)
- `_render_rule_evidence` (line 697) displays `alert.rule_confidence`
- `_render_ml_evidence` (line 723) displays `alert.ml_confidence`
- `_render_detection_analysis` (lines 651, 660, 670) correctly distinguishes rule/ml/combined confidences
- `get_detection_source_detail()` (dashboard_data.py:585-596) correctly separates rule/ml confidence from combined

No code changes needed.

---

### F2 — System Health missing `flows_in_progress` metric (LOW) — ALREADY IMPLEMENTED

**Status:** Already correctly implemented — `render_system_health()` (dashboard_components.py:921) displays `st.metric("Active Flows", ...)` from `stats.get("flows_in_progress", 0)`.

No code changes needed.

---

### F4 — `suppressed_count` never incremented (MEDIUM) — FIXED

**Files:** `alerts.py`

**Root cause:** `Alert.suppressed_count` field didn't exist on the dataclass. The dedup path incremented `count` but never tracked how many duplicates were suppressed.

**Fix:**
- Added `suppressed_count: int = 0` field to `Alert` dataclass
- In dedup path, increment `existing_alert.suppressed_count += 1` each time a duplicate is collapsed into the existing alert
- `count` = total observations; `suppressed_count` = duplicates beyond the first

**Verification:** 237/241 tests pass (same as baseline). No regressions.

---

### F6 — `INACTIVE` state not implemented (LOW) — FIXED

**Files:** `dashboard_data.py`, `dashboard.py`, `dashboard_components.py`, `tests/test_dashboard.py`

**Root cause:** `compute_system_health()` docstring mentioned `INACTIVE` but only returned STOPPED/DEGRADED/WARNING/HEALTHY. No distinction between "never started" and "stopped after running".

**Fix:**
- Added `ever_started: bool = False` parameter to `compute_system_health()`
- When `capture_running=False` and `ever_started=False` → returns `"INACTIVE"`
- When `capture_running=False` and `ever_started=True` → returns `"STOPPED"`
- Added `capture_ever_started` session state flag in `dashboard.py`, set to `True` when capture starts
- Updated `compute_kpis()` to accept and pass `ever_started`
- Updated all call sites to pass `ever_started=st.session_state.capture_ever_started`
- Updated `test_system_health_stopped` to pass `ever_started=True`
- Added new `test_system_health_inactive` test

**Verification:** 238 tests passed (includes new test). No regressions.

---

### P4 — DOS rate sub-rules fired on short flows (HIGH) — FIXED

**Files:** `config.py`, `rule_engine.py`, `tests/test_rule_engine.py`

**Root cause:** `high_packet_rate` and `high_byte_rate` divide a flow's packet/byte count by its duration. A completed TCP handshake to an **open** port is only 3–4 packets over about a millisecond, which divides out to thousands of packets/s and >100 kB/s. The only guard was `DOS_MIN_RATE_DURATION = 0.001` (1 ms), which such flows clear.

Observed in the live Kali → Ubuntu scan: the `192.168.56.105:37130 → 192.168.56.107:22` flow (4 packets, 280 bytes, 1.757 ms → 2,277 pps / 159 kB/s) fired both sub-rules, producing `DOS@0.80`, risk 92.8, severity **CRITICAL** — for a port that simply answered the scan.

**Fix:**
- Added `RuleConfig.DOS_MIN_RATE_PACKETS = 20`: minimum packets in a single flow before either rate sub-rule may fire.
- `_check_dos()` now derives `rate_is_reliable` from the duration guard **and** the new packet-count guard; both `high_packet_rate` and `high_byte_rate` use it.
- Per-flow `syn_flood_pattern` and `_check_dos_cross_flow()` are unchanged, so genuine floods are still caught, including floods built from many 1–2 packet flows.

**Verification:**
- Rule-engine suite: **12/12 PASS**, including the new regression test `test_connect_scan_open_port_not_dos` (a 4-packet handshake at 3,333 pps / 187 kB/s must not be DOS).
- Replayed the 3 saved DOS alerts from `nids_result.json` through the fixed engine using their stored feature snapshots: **0/3 still DOS** (all now BENIGN) — the scan handshake, a 2-packet DHCP exchange, and a 12-packet background SSH flow.
- Detection preserved: genuine flood (1000 pkts / 64 kB / 58 ms) → DOS@0.95; cross-flow SYN flood (200 one-packet flows) → DOS via `syn_flood_cross_flow`; 320-port scan → PORT_SCAN.
- **Live validation:** the same scan before the fix produced 339 alerts including 3 CRITICAL DOS; after the fix it produced 329 alerts with **0 DOS and 0 CRITICAL**, while still detecting 311 PORT_SCAN and 12 RECONNAISSANCE.

**Limitation:** 20 packets is a heuristic. A flow with fewer than 20 packets can no longer trigger per-flow DoS; very short bursts are covered only by the cross-flow SYN check.

---

### P5 — Refused scan probe scored as BRUTE_FORCE (MEDIUM) — FIXED

**Files:** `config.py`, `rule_engine.py`, `tests/test_rule_engine.py`

**Root cause:** the per-flow brute-force check treated any short flow on a listed service port, with few packets and no PSH data, as a failed authentication attempt. A port scan to a **closed** port has exactly that shape: SYN answered by RST+ACK — 2 packets, ~145 µs. In the post-P4 live run the `192.168.56.105:47250 → 192.168.56.107:445` probe was scored **HIGH BRUTE_FORCE** (risk 47.2, rule `short_auth_attempt`).

**Fix:**
- Added `RuleConfig.BRUTE_FORCE_RST_IS_REFUSAL = True`.
- `_check_brute_force()` excludes flows containing a TCP RST from the per-flow `short_auth_attempt` check.
- Immediate refusals (RST before a SYN-ACK) are also excluded from the cross-flow attempt counter; connections with a SYN-ACK remain eligible for campaign detection.

**Verification:**
- Rule-engine suite: **13/13 PASS**, including the new regression test `test_refused_probe_not_brute_force`, which also asserts that six repeated connections to port 22 still classify as BRUTE_FORCE.
- Replayed the saved port-445 alert from `nids_result.json`: BRUTE_FORCE → **BENIGN**, no rules triggered.
- **Live retest** (capture on `enp0s8`, same 25 pps scan from Kali): 820 packets → 403 flows → 403 alerts = **385 PORT_SCAN + 12 RECONNAISSANCE + 6 BENIGN**, with **0 DOS** and **0 BRUTE_FORCE** alerts. Severities were only INFORMATIONAL (6) and MEDIUM (397): no CRITICAL or HIGH at all. Scan result unchanged (`22/tcp open`, 799 closed, 32.1 s).

**Limitation:** an authentication attempt refused before the TCP handshake completes is not counted as an attempt; this heuristic does not inspect application-layer authentication data.

---

### P6 — Cross-flow SYN rate false positives on scan bursts (HIGH) — FIXED

**Files:** `config.py`, `rule_engine.py`, `tests/test_rule_engine.py`

**Root cause:** `_check_dos_cross_flow()` divided SYNs by the elapsed time from the first retained SYN to the latest. A short burst during a low-rate scan could therefore exceed the 100 pps DoS threshold despite the overall scan being capped at 25 pps.

**Fix:**
- Added `RuleConfig.DOS_CROSS_FLOW_WINDOW = 1.0` and calculate SYN rate over that full rolling one-second window, including during startup.
- Refused SYN→RST probes without a SYN-ACK are excluded from brute-force campaign counts. Handshakes containing SYN and SYN-ACK remain eligible.
- Added regressions for a 25 SYN/s scan, a sustained 200 SYN/s flood, and repeated refused probes to one closed service.

**Verification:**
- Rule-engine suite on Windows: **15/15 PASS**.
- Rule-engine main runner on Ubuntu: **15/15 PASS**.
- Full local pytest suite: **187 passed, 1 skipped, 0 failed** (104 warnings).
- Live Kali→Ubuntu scan after the fix (1,000 TCP ports, capped at 25 pps): port 22 open, 999 closed; the NIDS reported **12 PORT_SCAN, 12 RECONNAISSANCE, 4 BENIGN, 0 DOS** alerts for the Kali→Ubuntu pair.
- The bounded capture processed 926 packets; 254 flows were still in progress when it stopped, so the live alert totals are not a complete per-probe tally.

**Limitation:** The model still emits a scikit-learn version warning (artifact saved with 1.5.2, runtime 1.9.1), and has not been validated on live lab traffic.

---

## Known Limitation — ML model not validated on live lab traffic

The trained model (`models/nids_model.joblib`, last written 2026-11-09) was **not changed** by P4/P5 and does not drive the detections above:

- In the post-P5 live run it labelled **398 of 401** matched scan alerts BENIGN, with a mean BENIGN confidence of **0.9957** (confidently wrong, not merely uncertain). Only 3 flows were labelled PORT_SCAN.
- Final classification disagreed with the ML prediction on **394 of 401** alerts; the rule engine carried the detection.
- The artifact was pickled with scikit-learn **1.5.2** and runs under **1.9.1** on Ubuntu, so it also emits `InconsistentVersionWarning` at load time.

Treat the system as **rule-based detection with ML fusion**, not as an ML detector, until the model is retrained on lab-representative traffic.

---

## Test Status

| Suite | Result |
|-------|--------|
| `test_alerts`, `test_rule_engine`, `test_risk_scorer`, `test_correlator` | ALL PASS |
| `test_pipeline`, `test_concurrency`, `test_regression`, `test_dashboard` | ALL PASS |
| `test_evaluation` | 24/24 PASS |
| `test_stage10`, `test_attribution_regression` | ALL PASS |
| `test_collector_11_8_7` | 17/17 PASS |
| `test_stage11_8_7_split` | 3 failures (pre-existing test bugs) |
| `test_phase1_smoke`, `test_live_e2e*` | NOT RUN (need admin + loopback interface) |

**After P1 + P2 + P3 + F4 + F6 fixes:** 238 passed, 3 failed (pre-existing test bugs), 1 error (pre-existing fixture issue). No regressions introduced.

**After P4 (DOS rate gate):** `test_rule_engine` 12/12 PASS; DOS alerts replayed from the live Kali → Ubuntu run: 0/3 still classified DOS.

**After P5 (RST-aware brute force):** `test_rule_engine` 13/13 PASS; the saved port-445 BRUTE_FORCE alert replays as BENIGN.

**Live retest after P5:** 403 alerts from the same scan — 385 PORT_SCAN, 12 RECONNAISSANCE, 6 BENIGN; 0 DOS, 0 BRUTE_FORCE, no CRITICAL/HIGH severity.

---

## Recommended Next Steps (Priority Order)

1. Add unit test reproducing P1 expiry behavior to prevent regression
2. Calibrate thresholds (`config.py`) against real lab traffic
3. Retrain the model under scikit-learn 1.9.1 and include live lab captures (the 18-feature snapshots in `nids_result.json` are a starting set), then measure its recall on the scan traffic

---

## Project Assessment for Course Project

**Not too complicated.** This NIDS project is well-suited for a course project because:

- Core pipeline is already built and working
- Trained ML model included (`models/nids_model.joblib`)
- Streamlit dashboard included
- Full test suite included
- Runs locally (no AWS, no cloud costs, no React/Django stack needed)
- Modular architecture (can demo subsets if time-constrained)

**Compared to CloudGuard project:** NIDS is simpler to deploy (local Python vs. AWS + React + PostgreSQL + boto3) and already has working code.

**Realistic course-project scope:** Fix P1 + P3, demo pipeline with a PCAP/simulated traffic on the dashboard, document architecture and fixes. Skip Stage 11 evaluation and advanced dashboard polish unless aiming for extra credit.

---

*Last updated: 2026-11-11 (P4 DOS rate gate, P5 RST-aware brute force, P6 fixed-window SYN rate; live Kali → Ubuntu retest)*
