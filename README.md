# NIDS (Network Intrusion Detection System)

A Python-based, flow-oriented Network Intrusion Detection System ("NIDS Sentinel") that captures or replays network traffic, aggregates packets into bidirectional flows, detects suspicious behavior using a hybrid rule engine + machine learning model, and presents alerts/risk scores in a Streamlit dashboard.

> **Status note:** This repository contains the core implementation, tests, and extensive evaluation artifacts/reports. Live packet capture and isolated non-loopback lab validation are environment-dependent and are documented as partially unverified/blocked in project reports (see `evaluation/TEST_STATUS.md` and `docs/NIDS_AUDIT_REPORT.md`).

## How the project works

### 1. Packet ingestion
- **Live capture:** `packet_capture.py` uses Scapy to sniff packets from a network interface.
- **PCAP replay:** `dashboard.py` can replay uploaded `.pcap/.pcapng` files through the same pipeline.
- Parsed packet information (5-tuple, protocol, flags, sizes, timestamps) is fed into the flow tracker.

### 2. Flow tracking and feature extraction
- `flow_manager.py` groups packets into bidirectional flows keyed by the canonical 5-tuple (source/destination IP, source/destination port, protocol).
- `flow.py` maintains per-flow state (packet/byte counts per direction, TCP flag counts, timing, packet size stats, etc.).
- When a flow is completed/expired, `flow.get_features()` produces the feature vector used for detection.
- `features.py` defines the canonical **18-feature** schema shared by extraction, training, and inference.

### 3. Detection engines
Each completed flow is analyzed by two complementary detection paths:

- **Rule engine (`rule_engine.py`, configured in `config.py`)**
  - Applies threshold/stateful heuristics for attack patterns such as DoS/flooding indicators, port scanning, brute-force behavior, and reconnaissance.
  - Uses per-flow and cross-flow/time-window logic (where applicable) and returns a rule prediction, confidence, and triggered rule reasons.

- **Machine learning model (`model.py`)**
  - Uses a trained `StandardScaler` + `RandomForestClassifier` bundle (saved/loaded via joblib, default `models/nids_model.joblib`).
  - Predicts a traffic class and confidence/probabilities from the same 18 flow features.
  - Training utilities: `train_model.py`, `retrain_model.py`, `data_extractor.py` (CICIDS2017-based feature extraction/label mapping workflow in this project).

### 4. Correlation, risk scoring, and alerting
- **Correlation (`correlator.py`)** fuses rule-engine and ML outputs into a single detection result (handles agreement/disagreement/one-sided cases and produces combined confidence/context).
- **Risk scoring (`risk_scorer.py`)** maps the final prediction/confidence to a risk score and severity.
- **Alert management (`alerts.py`)** creates alert records with detection/risk metadata, explanation/context, deduplication/rate-limiting behavior, and in-memory alert storage/statistics.

### 5. Pipeline orchestration
- `pipeline.py` (`NIDSPipeline`) wires the full chain:
  1. `FlowManager` processes packets and emits completed flows
  2. Feature extraction (`flow.get_features()`)
  3. `RuleEngine.process_flow(flow)`
  4. `CorrelationEngine.correlate(...)`
  5. `RiskScorer.score(...)`
  6. `AlertManager.create_alert(...)`
- The pipeline is designed with per-stage error handling so one bad flow/stage failure does not crash the whole run.
- `ProcessingWorker` (in `pipeline.py`) supports queue-based/background packet processing so capture/producer and processing can be decoupled (used by the dashboard/UI flow).

### 6. Dashboard (UI)
- `dashboard.py` is a Streamlit app ("Sentinel") that:
  - initializes a `NIDSPipeline`
  - starts/stops live capture in a background worker thread, or replays a PCAP
  - periodically refreshes KPIs, charts, and recent alerts
  - shows alert details (severity, attack type, rule/ML outputs, risk, explanation, etc.)
- `dashboard_data.py` (and related dashboard modules, if present) provide aggregation/helpers for UI metrics.

## Project structure

```text
NIDS/
├── alerts.py                # Alert creation, dedup/rate-limit, alert storage
├── config.py                # Flow/rule thresholds and severity mapping
├── correlator.py            # Rule + ML fusion logic
├── dashboard.py             # Streamlit dashboard UI
├── dashboard_data.py        # Dashboard KPI/aggregation helpers
├── data_extractor.py        # Dataset feature extraction / label mapping helpers
├── features.py              # Canonical 18-feature schema
├── flow.py                  # Flow model and feature computation
├── flow_manager.py          # Packet-to-flow tracking and expiration
├── model.py                 # ML model wrapper (load/predict/train utilities)
├── packet_capture.py        # Scapy capture/parsing utilities
├── pipeline.py              # End-to-end pipeline orchestration
├── retrain_model.py         # Retraining workflow/script
├── risk_scorer.py           # Risk/severity scoring
├── rule_engine.py           # Stateful/threshold-based detection rules
├── train_model.py           # Model training script
├── requirements.txt         # Python dependencies
├── docs/                    # Notes, audit, requirements docs, papers
├── evaluation/              # Evaluation harness, datasets metadata, reports, results
└── tests/                   # Unit/integration/regression/live-oriented tests
```

## Requirements

- Python 3.12+ recommended (project has been developed/tested in that environment)
- Dependencies listed in `requirements.txt`:
  - `pandas`
  - `scapy`
  - `scikit-learn`
  - `joblib`
  - `streamlit`
- **Live capture requirements (platform-dependent):**
  - Appropriate packet-capture permissions
  - On Windows: Npcap and often Administrator privileges for live sniffing

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Run the dashboard (Streamlit)
From the `NIDS` project directory:

```bash
streamlit run dashboard.py
```

Notes:
- The dashboard expects a trained model at `models/nids_model.joblib` by default.
- You can start live capture from the UI (interface selection supported) or replay a `.pcap/.pcapng` file.
- Live capture behavior depends on OS/interface permissions and Scapy/Npcap availability.

### Train a model
The training script downloads/loads a CICIDS2017 sample dataset, extracts features, trains a Random Forest model, evaluates it, and saves it to `models/nids_model.joblib`:

```bash
python -m NIDS.train_model
```

(Adjust the command/module invocation to your working directory/package layout as needed.)

### Programmatic/pipeline usage
The core orchestration lives in `pipeline.py` (`NIDSPipeline`, `ProcessingWorker`). It can be used to process packets/flows through the full detection chain and access generated alerts/statistics.

## Evaluation and testing

- `tests/` contains unit, integration, regression, and live-capture-related tests.
- `evaluation/` contains data collection/analysis scripts, stage reports, metrics, and benchmark artifacts.
- `evaluation/TEST_STATUS.md` and `docs/NIDS_AUDIT_REPORT.md` document recent offline test results, known limitations, and audit findings (including live-capture constraints and identified correctness issues to address).

Example offline test command (as documented in project status):

```bash
python -m pytest tests -q --tb=short --disable-warnings --ignore=tests/test_live_e2e.py --ignore=tests/test_live_e2e_corrected.py --ignore=tests/test_phase1_smoke.py --ignore=tests/test_stage9_live.py
```

## Known limitations / notes

- Some detection thresholds are initial and may require calibration for your environment.
- Live capture and end-to-end VM/lab validation depend on network/interface/permission setup.
- Audit reports in `docs/` describe known issues and improvement areas (e.g. flow timeout behavior, label-mapping robustness, alert dedup confidence semantics).
- Large datasets, generated evaluation artifacts, and model binaries may be excluded from this GitHub repo by `.gitignore` to keep the repository size manageable.

## Additional documentation

- `docs/NIDS_AUDIT_REPORT.md` — architecture/code audit and findings
- `docs/NIDS_NOTES.md` — project notes
- `docs/DASHBOARD_REQUIREMENTS.md` — dashboard requirements/design notes
- `evaluation/TEST_STATUS.md` — latest recorded offline test/evaluation status
- `evaluation/datasets/README.md` — evaluation dataset provenance/notes
- `evaluation/datasets/STAGE11_*` — stage reports and validation analyses
