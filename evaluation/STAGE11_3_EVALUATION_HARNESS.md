# STAGE 11.3: EVALUATION HARNESS DOCUMENTATION

## Architecture

```
NIDS/evaluation/
├── schema.py              # Data schema, EvaluationRecord, EvaluationDataset
├── collect_loopback.py    # Benign loopback traffic collector
├── collect_attacks.py     # Safe attack collection framework
├── evaluate.py            # Evaluation engine (metrics, reports)
├── validation.py          # Dataset and record validation
├── splitting.py           # Temporal/session-based splitting
├── datasets/              # Output directory for collected data
│   ├── loopback_benign_*.jsonl
│   └── attack_*.jsonl
├── stage11_1_leakage_free.py  # Stage 11.1 IID baseline (reference)
└── STAGE11_3_EVALUATION_HARNESS.md  # This file
```

## Data Schema

### EvaluationRecord

Each record represents a single labeled flow. Fields:

| Field | Type | Description |
|-------|------|-------------|
| evaluation_session_id | str | Unique session identifier |
| collection_timestamp | float | Unix timestamp of flow start |
| traffic_category | str | "BENIGN" or "ATTACK" |
| traffic_subtype | str | e.g. "loopback_tcp", "nmap_scan" |
| ground_truth_label | str | One of 5 class labels |
| src_ip, dst_ip | str | Flow endpoints |
| src_port, dst_port | int | Flow ports |
| protocol | int | 1=ICMP, 6=TCP, 17=UDP |
| features | List[float] | 18 ML features in canonical order |
| model_prediction | str | ML model output (None during collection) |
| model_confidence | float | ML confidence (None during collection) |
| model_probabilities | Dict | Per-class probabilities (None during collection) |
| rule_prediction | str | Rule Engine output (optional) |
| rule_confidence | float | Rule confidence (optional) |
| rule_triggered | List[str] | Triggered rule names (optional) |
| correlation_prediction | str | Correlation Engine output (optional) |
| correlation_confidence | float | Correlation confidence (optional) |
| alert_generated | bool | Whether alert was created (optional) |
| alert_risk_score | float | Alert risk score (optional) |
| alert_severity | str | Alert severity (optional) |
| flow_duration | float | Flow duration in seconds (optional) |
| packet_count | int | Number of packets (optional) |
| byte_count | int | Total bytes (optional) |
| collection_interface | str | Capture interface name |
| source_machine | str | Machine that generated traffic |
| target_machine | str | Machine that received traffic |
| generator_command | str | Traffic generation command |
| generator_log | str | Generator stdout/stderr |
| extra_metadata | Dict | Additional metadata |

### Validation Verdicts

- **VALID**: Record is clean and ready for evaluation
- **WARNING**: Non-critical issues (e.g., extreme feature values)
- **INVALID**: Critical issues (e.g., wrong label, missing features)

## Labeling Methodology

Ground truth is assigned **independently of NIDS predictions**:

1. **Benign traffic**: Labeled BENIGN by the collection script because the traffic generator is known to produce benign traffic (ping, TCP connect, DNS query, etc.).
2. **Attack traffic**: Labeled by the attack type specified in the collection configuration (e.g., "PORT_SCAN"). The label is assigned before any NIDS processing occurs.
3. **No NIDS-in-the-loop labeling**: The NIDS model, rule engine, correlator, and alert manager are never used to assign ground truth labels.

## Collection Process

### Benign Loopback

1. Configure `LoopbackCollectionConfig` with session ID, duration, and traffic parameters.
2. Call `collector.collect()` to capture and extract flows.
3. Call `collector.save()` to write to JSON Lines.
4. All flows are labeled BENIGN automatically.

### Attack Collection (Safe Framework)

1. Configure `AttackCollectionConfig` with session ID, attack type, target, authorization.
2. Create `AttackSessionPlan` via `plan_attack_session(config)`.
3. Review the plan for safety violations.
4. If safe, call `collector.collect()` to execute.
5. Call `collector.save()` to write to JSON Lines.

**Safety checks enforce:**
- Target IP must be in the allowed list (default: loopback, 192.168.56.0/24, 10.0.0.0/24)
- Interface restrictions (loopback only for 127.0.0.1)
- Authorization requirement (authorized_by must be non-empty)
- Maximum duration (600 seconds)

## Leakage Prevention

1. **Session-based splitting**: Sessions are the atomic unit of splitting, never individual flows.
2. **Temporal holdout**: Train on earlier sessions, test on later sessions.
3. **Source IP separation**: For cross-flow attacks, test source IPs must not appear in training.
4. **Duplicate removal**: Exact-duplicate feature vectors are flagged during validation.
5. **No random shuffling**: Random splits are not used as the primary evaluation method.

## Evaluation Metrics

### Classification Metrics
- Accuracy, Precision, Recall, F1 (macro and weighted)
- Confusion matrix
- Per-class support, FPR, FNR

### Operational Metrics
- Alerts per hour
- False alerts per hour
- Detection latency (mean, p95)
- Flow processing failures

### Confidence Metrics
- Mean confidence for correct vs incorrect predictions
- Confidence distribution (binned)
- Per-class confidence statistics

### Distribution Metrics
- Feature means and standard deviations
- Train-vs-evaluation Wasserstein distances

## Safety Boundaries

- Evaluation code runs entirely under `NIDS/evaluation/`
- No production code is modified
- No model artifacts are overwritten
- Attack collection requires explicit authorization
- Target networks are restricted to lab ranges
- Maximum attack duration is 600 seconds

## Adding Future Traffic

To add new benign or attack traffic:

1. **Benign**: Extend `LoopbackCollector` or create a new collector class in `collect_loopback.py`.
2. **Attack**: Create a new attack type in `collect_attacks.py` by extending `SUPPORTED_ATTACK_TYPES` and adding generation logic.
3. **Schema changes**: If new fields are needed, update `EvaluationRecord` in `schema.py`.
4. **Tests**: Add corresponding tests in `test_evaluation.py`.

## How to Run

```bash
# Run evaluation tests
python -m pytest NIDS/tests/test_evaluation.py -v

# Collect benign loopback traffic
python -m NIDS.evaluation.collect_loopback

# Plan an attack collection session (safe, does not execute)
python -m NIDS.evaluation.collect_attacks

# Run evaluation on a dataset
python -m NIDS.evaluation.evaluate --dataset NIDS/evaluation/datasets/xxx.jsonl
```

## Current Limitations

1. **No attack traffic yet**: The attack collector is a safe framework; actual attack generation requires manual operator action.
2. **No loopback dataset yet**: The benign collector works but has not been run to produce a dataset.
3. **Limited traffic generators**: Only ICMP, TCP, UDP, and DNS are implemented for benign collection.
4. **No automated PCAP saving**: PCAP export is supported in config but not fully implemented.
5. **No model inference in collector**: Collectors only extract flows; model evaluation is done offline by `evaluate.py`.
