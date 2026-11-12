# Stage 11.8.2 Implementation Plan

## Current State (Stage 11.8)
- Uses raw sockets + DirectFlowTracker
- No TCP flags captured (all zeros)
- Custom flow tracking instead of production FlowManager
- Deterministic attack patterns → 84.5% duplicate feature vectors
- DOS: only 20 flows (generator parameter)
- RECON: sequential IP scanning → detection only at flow #401
- Latency measurement contaminated by collection duration

## Required Changes (Evaluation-Only)

### 1. Replace DirectFlowTracker with Production FlowManager + Scapy Capture
- Use `sniff(iface='Loopback Pseudo-Interface 1')` to capture real packets
- Feed packets to `FlowManager.process_packet()` for flow tracking
- This preserves TCP flags, timestamps, and all 18 production features
- No production code changes

### 2. Attack Generators
- Keep generators but make them more diverse:
  - PORT_SCAN: randomize port order, vary timing
  - BRUTE_FORCE: vary connection intervals
  - DOS: increase flows parameter to 100+, vary packet sizes
  - RECON: randomize IP order (interleaved)
- Generators still use raw sockets (that's fine - Scapy captures the packets)

### 3. Latency Measurement
- Use Scapy packet timestamps (`packet.time`) as capture time
- Use flow completion time from FlowManager
- Use alert creation time from AlertManager
- Calculate: `alert_timestamp - first_packet_timestamp`

### 4. Diversity Improvements
- Vary payload sizes
- Vary inter-packet intervals
- Vary burst patterns
- Randomize scan orders

### 5. Pilot First
- Collect 20 flows per class
- Verify TCP flags are non-zero
- Verify 18 features are populated
- Verify attribution works
- Then collect full dataset

## Files to Create/Modify
- Create: `NIDS/evaluation/collect_attack_11_8_v2.py` (new Scapy-based collector)
- Keep: `NIDS/evaluation/collect_attack_11_8.py` (unchanged, for reference)
- Create: `NIDS/evaluation/stage11_8_2_pilot_report.md`
- Create: `NIDS/evaluation/datasets/stage11_8_2_*.jsonl` (new datasets)

## Safety Guarantees
- No production files modified
- Model hash unchanged: `7bcc643154a1f44d`
- No retraining
- No threshold changes
- No rule changes
