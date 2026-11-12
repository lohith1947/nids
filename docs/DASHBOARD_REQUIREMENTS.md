# NIDS Dashboard — Build Requirements

> **Give this whole document to the AI that will build the dashboard.**
> It contains everything needed: context, the exact engine API, UI spec, and rules.
> The detection engine is **finished and tested** — do not modify it. Only add new UI files.

---

## 1. Context

- Project: **NIDS "Sentinel"** — a flow-based Network Intrusion Detection System (course project).
- Location: `C:\Users\SRIRAM NAIDU\Desktop\AI agent\NIDS\`
- Language/stack: Python 3.12. Engine deps: Scapy, scikit-learn, joblib, pandas.
- The project root folder **is** the Python package `NIDS` (it has `__init__.py`; modules import each other with `from .alerts import ...`).
- A trained model already exists at `NIDS\models\nids_model.joblib` (RandomForest + StandardScaler, 5 classes).

**Pipeline architecture (already built, working, 238 tests passing):**

```
Scapy capture → FlowManager → RuleEngine → CorrelationEngine → RiskScorer → AlertManager
                              └────────→ ML model (RandomForest) ────────┘
```

An older, over-engineered dashboard was deleted on purpose. **This time the dashboard must be SIMPLE.**

## 2. Goal and constraints

Build **one single-page Streamlit dashboard** that lets a user:

1. Start/stop packet capture (or replay a PCAP file for demo without admin rights)
2. Watch live stats (packets, flows, alerts)
3. See and inspect alerts

**Constraints:**

- **Simple. Course project.** Single file `dashboard.py` in the project root is preferred (max 2–3 files).
- Streamlit only. No React, no FastAPI, no database, no login, no Docker.
- No changes to engine modules (`pipeline.py`, `alerts.py`, etc.). Use only the public API below.
- Must render a sensible **empty state** when no capture has started yet.
- Must run on Windows (primary) with `python -m streamlit run dashboard.py`.

## 3. Tech stack

| Item | Choice |
|---|---|
| UI framework | Streamlit (`streamlit>=1.37`) — add it to `requirements.txt` |
| Charts | Built-in `st.metric`, `st.bar_chart`, `st.dataframe` — no extra chart libs |
| Data handling | pandas (already a dependency) |
| Live capture | Scapy via the engine (needs admin/Npcap on Windows) |
| Demo fallback | PCAP replay via Scapy `rdpcap` (no admin needed) |

## 4. File layout

```
NIDS/
├── dashboard.py          ← NEW: the entire dashboard (single file)
├── requirements.txt      ← add: streamlit>=1.37
├── models/nids_model.joblib
├── alerts.py, pipeline.py, ...   ← existing engine (DO NOT MODIFY)
└── docs/                 ← existing docs
```

`dashboard.py` must import the engine like this (the parent of the project
folder must be on `sys.path` so the folder is importable as package `NIDS`):

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from NIDS.pipeline import NIDSPipeline
```

Run it from inside the project folder: `python -m streamlit run dashboard.py`

## 5. Engine public API (the ONLY things the dashboard may call)

One class: `NIDSPipeline` from `NIDS.pipeline`.

```python
from NIDS.pipeline import NIDSPipeline

pipeline = NIDSPipeline()   # loads models/nids_model.joblib by default
```

| Method | Returns | Notes |
|---|---|---|
| `start_capture(interface=None, count=0)` | None | **BLOCKING.** Runs until Ctrl-C. Must run in a daemon thread. `interface=None` lets Scapy pick the default. |
| `stop()` | None | Sets a stop flag. **Limitation:** cannot interrupt a blocking sniff; the thread may linger until the app exits. UI should still mark itself "stopped". |
| `process_packet(packet)` | `List[Alert]` | Feed one Scapy packet manually — **use this for PCAP replay mode.** |
| `get_stats()` | dict | `packets_processed, flows_completed, flows_processed, alerts_created, flows_failed, flows_in_progress, alerts_suppressed, last_packet_ts` |
| `get_alerts()` | `List[Alert]` | All stored alerts (thread-safe copy). |
| `get_recent_alerts(n=10)` | `List[Alert]` | N most recent, newest first. |
| `count_alerts_by_severity()` | `Dict[str, int]` | e.g. `{"HIGH": 3, "CRITICAL": 1}` |
| `count_alerts_by_attack_type()` | `Dict[str, int]` | e.g. `{"DOS": 1, "PORT_SCAN": 2}` |
| `finalize_flows()` | `List[Alert]` | Best-effort processing of unfinished flows (optional, on stop). |

**Thread-safety contract:** stats and alert getters are lock-protected and safe
to call from the Streamlit main thread while capture runs in another thread.
Never call `start_capture` twice concurrently — guard with an idempotency check.

## 6. The `Alert` object (from `NIDS.alerts`)

Dataclass fields — everything the UI needs is already on the alert:

| Field | Type | Meaning |
|---|---|---|
| `alert_id` | str (uuid) | unique id |
| `timestamp` | float | unix time of creation |
| `attack_type` | str | `BENIGN`, `PORT_SCAN`, `RECONNAISSANCE`, `BRUTE_FORCE`, `DOS` |
| `risk_score` | float | 0–100 |
| `severity` | str | `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `confidence` | float | 0–1 combined (rule + ML) |
| `source_ip`, `destination_ip` | str | endpoints |
| `source_port`, `destination_port` | int | endpoints |
| `protocol` | int | 6=TCP, 17=UDP, 1=ICMP |
| `triggered_rules` | `List[str]` | rule names that fired, e.g. `["syn_only_probe"]` |
| `rule_prediction`, `rule_confidence` | str, float | rule-engine verdict |
| `ml_prediction`, `ml_confidence` | str, float | ML verdict |
| `explanation` | str | human-readable reason — show this in detail view |
| `count` | int | times this same alert repeated (dedup) |
| `first_seen`, `last_seen` | float | dedup window tracking |
| `suppressed` | bool | rate-limited alert |
| `suppressed_count` | int | duplicates collapsed into this alert |
| `ml_top3` | optional `[(label, prob), ...]` | ML's top-3 probabilities |
| `feature_snapshot` | optional `List[float]` | 18 flow features (optional detail) |
| `to_dict()` | dict | serialization helper |

**Reference values:**

- Severity per attack class (`config.py` SEVERITY_MAP): `BENIGN→INFORMATIONAL`, `PORT_SCAN→MEDIUM`, `RECONNAISSANCE→MEDIUM`, `BRUTE_FORCE→HIGH`, `DOS→CRITICAL`
- Severity order (low→high): INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
- AlertManager defaults: dedup window 30 s, rate limit 10 alerts/source/30 s, suppressed alerts are kept in the store.

## 7. UI specification — one page, four sections

```
┌────────────────────────────────────────────────────────┐
│ NIDS Sentinel (title + status pill: INACTIVE/CAPTURE ON)│
├────────────────────────────────────────────────────────┤
│ [1] CONTROLS                                            │
│   interface text input (default "auto")                 │
│   [Start capture] [Stop] [Replay PCAP file picker]     │
├────────────────────────────────────────────────────────┤
│ [2] KPI ROW (st.metric ×5)                              │
│   Packets | Flows | Alerts | Suppressed | In-progress   │
├────────────────────────────────────────────────────────┤
│ [3] CHARTS (two st.bar_chart side by side)              │
│   alerts by severity  |  alerts by attack type          │
├────────────────────────────────────────────────────────┤
│ [4] ALERT TABLE (st.dataframe)                          │
│   filters: severity dropdown, attack type dropdown,     │
│   "show benign/informational" toggle (default OFF)     │
│   newest first, latest 200 alerts                       │
│   st.expander per alert → explanation, triggered rules,│
│   rule/ML predictions + confidences, ML top-3           │
└────────────────────────────────────────────────────────┘
```

### Section details

**[1] Controls**
- `interface`: text input, empty/`auto` → pass `None` to `start_capture`.
- **Start**: spawn `pipeline.start_capture(interface)` in a `threading.Thread(daemon=True)`. Idempotent: if already running, do nothing. Set a session-state flag `capture_running=True`.
- **Stop**: call `pipeline.stop()`, set `capture_running=False`. Show info note that the OS-level sniff stops taking effect at the next packet / app exit (engine limitation — known and fine).
- **Replay PCAP**: file picker (`.pcap/.pcapng`); on click, read with `scapy.utils.rdpcap(path)` and loop packets through `pipeline.process_packet(pkt)` (optionally `time.sleep(0.005)` between packets so the UI feels live). Run in a daemon thread too; guard with the same running flag.

**[2] KPI row** — from `pipeline.get_stats()`:
`packets_processed`, `flows_completed`, `alerts_created`, `alerts_suppressed`, `flows_in_progress`.

**[3] Charts** — `count_alerts_by_severity()` and `count_alerts_by_attack_type()` as two `st.bar_chart`s. Use the fixed severity order for display. Empty dict → show "No alerts yet" placeholder.

**[4] Alert table** — `pipeline.get_alerts()` (newest first, cap at 200 rows):
- Columns: time (HH:MM:SS), severity, attack_type, risk_score, source_ip:port → destination_ip:port, protocol (show "TCP"/"UDP"/"ICMP"), count
- Color-code severity cells (CRITICAL/HIGH red-ish, MEDIUM orange, LOW/INFORMATIONAL gray) — `st.dataframe` column_config or simple emoji prefix is fine.
- Default: **hide `BENIGN`/`INFORMATIONAL`** (the engine emits benign alerts too). Toggle to include.
- Detail via `st.expander`: `explanation`, `triggered_rules`, `rule_prediction (rule_confidence)`, `ml_prediction (ml_confidence)`, `ml_top3`, `risk_score`.

### Live refresh

- Wrap the KPI/charts/table sections in `st.fragment(run_every="2s")` (Streamlit ≥1.37) so they auto-refresh without rerunning the whole page.

## 8. Behavior rules (Streamlit gotchas — follow exactly)

1. **One pipeline per session.** Streamlit reruns the script on every interaction. Store the pipeline and worker thread in `st.session_state` (or `@st.cache_resource`) so alerts are not wiped on rerun. Never construct `NIDSPipeline()` twice for the same session.
2. **Idempotent start.** Before starting capture, check the running flag AND `thread.is_alive()`; a double-click must not spawn two sniff threads.
3. **Empty state.** Before any capture starts, the page must render with zeros/`—` and a friendly "No capture running — start capture or replay a PCAP" message. No exceptions, no crashes.
4. **Model check.** Wrap `NIDSPipeline()` creation in try/except; if `models/nids_model.joblib` is missing/corrupt, show `st.error("Trained model not found at models/nids_model.joblib — run train_model.py first")` and stop.
5. **UI reads only.** The UI thread only calls the getters in §5. All packet processing happens in the worker/capture thread.
6. **No engine edits.** If something seems missing from the API, work around it in `dashboard.py`; do not touch engine files.

## 9. Run instructions (for the final README section)

```powershell
cd "C:\Users\SRIRAM NAIDU\Desktop\AI agent\NIDS"
python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
```

- **Replay mode** (demo, no admin): pick any `.pcap` in the UI.
- **Live mode** (real capture): run the terminal as Administrator on Windows (Npcap required). On Linux needs root/`CAP_NET_RAW`.
- Generating test traffic to see alerts: `nmap` a host (PORT_SCAN/RECONNAISSANCE), `hping3 -S --flood` (DOS), repeated SSH failures (BRUTE_FORCE).

## 10. Acceptance checklist

- [ ] `python -m streamlit run dashboard.py` starts with no errors and shows empty state
- [ ] Replay of any pcap populates KPIs, charts, and the alert table within ~5 s
- [ ] Start/Stop buttons work; double-start does not spawn a second thread
- [ ] Severity and attack-type charts match `count_alerts_by_severity()` / `count_alerts_by_attack_type()`
- [ ] Alert table hides BENIGN by default; toggle shows them
- [ ] Alert detail expander shows explanation, triggered rules, rule/ML predictions, ml_top3
- [ ] Page auto-refreshes every ~2 s during capture without losing state
- [ ] No engine file was modified (`git status` clean apart from new dashboard files — if git were used)
- [ ] Total: **one new file** (`dashboard.py`) + one line added to `requirements.txt`

## 11. Out of scope (do NOT build)

- Login/auth, multi-user, HTTPS
- Multiple pages / navigation sidebar
- Database persistence (alerts live in memory for the session — fine for a course demo)
- Export to CSV/PDF, email/Slack notifications
- Threshold tuning UI, rule editor
- Docker, cloud deploy, systemd
- WebSocket/REST API layer

---

*Written for hand-off to an AI builder. Engine audited 2026-11-11.*
