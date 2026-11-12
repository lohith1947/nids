# STAGE 11.2: REAL-WORLD / LOOPBACK EVALUATION DESIGN REPORT

**Status:** READ-ONLY DESIGN — NO PRODUCTION CODE, MODEL, OR TEST CHANGES
**Date:** 2026-09-09
**Designer:** Kilo (automated)

---

## 1. EXECUTIVE SUMMARY

**STAGE 11.2 VERDICT: YELLOW**

The NIDS has a validated IID baseline (clean accuracy 98.24%, macro F1 0.9260), but **zero** validated performance data on real-world or loopback traffic. The current model was trained exclusively on CICIDS2017, which contains no loopback flows. Stage 9 live validation confirms the pipeline can capture and process loopback traffic without crashes, but it does **not** measure detection accuracy or false-positive rate because it generates only benign traffic and uses rule-level pass/fail checks rather than ML-level ground-truth evaluation.

A rigorous, leakage-resistant evaluation design is required before the model can be deployed outside CICIDS2017. This document specifies that design.

---

## 2. EXISTING CAPABILITIES

### 2.1 Live Capture Infrastructure
- **FACT:** `NIDS/packet_capture.py` wraps Scapy `sniff()` with configurable interface, callback, count, and `stop_filter`.
- **FACT:** `NIDS/flow_manager.py` creates bidirectional flows, extracts 5-tuples, tracks TCP flags, and closes flows on 10-second inactivity timeout.
- **FACT:** `NIDS/pipeline.py` + `ProcessingWorker` provide a thread-safe capture → process → alert pipeline with graceful shutdown.
- **FACT:** `NIDS/tests/test_stage9_live.py` demonstrates end-to-end loopback capture of ICMP, TCP, UDP, and DNS traffic with 22 validation tests.

### 2.2 Traffic Generation
- **FACT:** Existing tests generate benign loopback traffic via:
  - `subprocess.run(["ping", "-n", "3", "127.0.0.1"])` → ICMP
  - `socket.connect(("127.0.0.1", port))` → TCP SYN/RST
  - `socket.sendto(b"benign_test_data" * 4, ("127.0.0.1", 12345))` → UDP
  - Scapy `IP(dst="127.0.0.1")/UDP(dport=53)/DNS(...)` → DNS
- **FACT:** No existing code generates malicious loopback traffic (PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE) in a controlled, labeled manner.

### 2.3 Ground Truth Availability
- **FACT:** CICIDS2017 provides labeled flows, but no loopback traffic.
- **FACT:** Stage 9 tests verify pipeline stability, not detection accuracy.
- **FACT:** No persisted labeled dataset exists for loopback or lab traffic.

### 2.4 Detection Categories
The Rule Engine detects:
1. **DOS** (per-flow): high packet rate, high byte rate, SYN-flood pattern
2. **PORT_SCAN** (cross-flow + per-flow): unique dst ports, SYN-only probes
3. **BRUTE_FORCE** (cross-flow + per-flow): repeated connections to service ports
4. **RECONNAISSANCE** (cross-flow): unique dst IPs, unique dst ports across targets

The ML model predicts the same 5 classes via Random Forest on 18 features.

### 2.5 Alert Structure
- **FACT:** `Alert` dataclass includes `feature_snapshot` (18 floats) and `ml_top3` (top-3 probabilities).
- **FACT:** `AlertManager` supports deduplication, rate limiting, and severity filtering.
- **FACT:** `dashboard_data.py` can aggregate alerts by attack type, severity, and detection source.

---

## 3. TRAFFIC CATEGORIES

### 3.1 BENIGN TRAFFIC

#### 3.1.1 Loopback TCP
- **Sources:** Local service connections (HTTP, HTTPS, SSH, database clients, IPC sockets).
- **Collection method:** Run common local services (e.g., `python -m http.server`, `ssh localhost`, `redis-server`) and capture traffic while clients interact normally.
- **Ground truth:** Traffic is benign by definition (local services responding to legitimate requests).
- **Valid sample:** A completed flow with normal bidirectional traffic, application data (PSH flags), and realistic durations (>0.01s).

#### 3.1.2 Loopback UDP
- **Sources:** DNS queries to `127.0.0.1` (if local resolver), mDNS, syslog, DHCP client.
- **Collection method:** Generate DNS queries via `dig @127.0.0.1`, `nslookup`, or application DNS lookups.
- **Ground truth:** DNS response traffic is benign.
- **Valid sample:** Request/response pairs with matching ports and realistic sizes.

#### 3.1.3 Loopback ICMP
- **Sources:** `ping 127.0.0.1`, `traceroute`, network health checks.
- **Collection method:** Automated ping with varying count and interval.
- **Ground truth:** ICMP echo request/reply is benign.
- **Valid sample:** Complete echo request + reply exchange.

#### 3.1.4 Normal TCP (non-loopback)
- **Sources:** Web browsing, SSH to external hosts, email, API calls.
- **Collection method:** Capture on the host-only interface (e.g., `192.168.56.x` on VirtualBox) during normal workstation use.
- **Ground truth:** Traffic to/from known legitimate destinations.
- **Valid sample:** Flows with complete TCP handshakes (SYN, SYN-ACK, ACK) and application data.

#### 3.1.5 Normal UDP (non-loopback)
- **Sources:** DNS to external resolvers, QUIC/HTTP3, VoIP signaling.
- **Collection method:** Same as TCP, on host-only interface.
- **Ground truth:** Traffic to known legitimate UDP services.

#### 3.1.6 ICMP (non-loopback)
- **Sources:** External ping, traceroute, path MTU discovery.
- **Collection method:** Same capture window as TCP/UDP.
- **Ground truth:** Standard ICMP types 0, 8, 11.

#### 3.1.7 Local VM/Lab Traffic
- **Sources:** Traffic between the Windows host and a Kali Linux VM on `192.168.56.0/24`.
- **Collection method:** Capture on the VirtualBox host-only adapter from both host and VM sides.
- **Ground truth:** Known traffic patterns from controlled lab scripts.
- **Valid sample:** Flows where both endpoints are in the lab subnet.

#### 3.1.8 Ordinary Application Traffic
- **Sources:** Browser tabs, IDEs, chat apps, package managers.
- **Collection method:** 30-minute background capture during active workstation use.
- **Ground truth:** Heuristic — flows that match known application signatures (e.g., TLS handshakes, HTTP keep-alive).
- **Caution:** This category is noisy and should be labeled conservatively.

### 3.2 ATTACK TRAFFIC

All attack traffic must be generated in a **controlled lab environment** (isolated VM or container network) with **no production network access**.

#### 3.2.1 PORT_SCAN
- **Tool:** `nmap -sS --top-ports 100 <target>` or custom Python SYN scanner.
- **Pattern:** Single source sends SYN packets to ≥10 distinct destination ports within 10 seconds.
- **Ground truth:** Packet capture shows ≥10 unique dst ports from same src IP in sliding window.
- **Valid sample:** Flow completes with SYN-only (no ACK), few packets, dst_port in scan list.
- **Contamination avoidance:** Run scans against a dedicated target VM; separate benign and attack collection windows by ≥5 minutes.

#### 3.2.2 BRUTE_FORCE
- **Tool:** `hydra -l admin -P passwords.txt ssh://<target>` or custom TCP connect flood to service ports.
- **Pattern:** ≥10 connection attempts from same src to same (dst_ip, dst_port) within 10 seconds.
- **Target ports:** 22 (SSH), 23 (telnet), 80 (HTTP), 443 (HTTPS).
- **Ground truth:** Auth-attempt flows are short (<1s), have no PSH data, and repeat rapidly.
- **Contamination avoidance:** Use a throwaway target VM; reset auth logs between runs.

#### 3.2.3 DOS
- **Tool:** `hping3 -S --flood -p <port> <target>` or `nping --tcp --rate 10000 <target>`.
- **Pattern:** Single flow with >500 packets/sec sustained for >50 packets, OR high byte rate, OR SYN ratio >0.8 with ≥20 SYNs.
- **Ground truth:** Traffic generator logs show flood parameters; packet capture confirms rates.
- **Valid sample:** Flow has high `packets_per_second` or `bytes_per_second`, duration >0.1s.
- **Contamination avoidance:** Flood a dedicated target VM; monitor target for actual service degradation to confirm attack efficacy.

#### 3.2.4 RECONNAISSANCE
- **Tool:** `nmap -sL <target_range>` or custom multi-host ping sweep.
- **Pattern:** Single source contacts ≥5 unique dst IPs within 10 seconds, OR ≥10 unique dst ports across targets.
- **Ground truth:** Packet capture shows distinct dst IPs/ports from same src.
- **Valid sample:** Multiple short flows to different hosts, few packets per flow.
- **Contamination avoidance:** Scan a dedicated target subnet; ensure no other traffic from the source IP during the window.

---

## 4. GROUND TRUTH STRATEGY

### 4.1 Authoritative Label Source
Ground truth must come from the **traffic generation system**, not from the NIDS.

- **FACT:** Each attack generator logs: timestamp, src/dst, port, packet count, byte count, duration, flags.
- **FACT:** For benign traffic, ground truth is established by the application/service generating the traffic (e.g., HTTP server access logs, DNS query logs).
- **FACT:** Packet capture (Scapy/pcap) provides the raw evidence; flows are derived offline from the pcap.

### 4.2 Flow Labeling Protocol
1. **Capture:** Record raw packets to a pcap file during each collection window.
2. **Extract:** Use `FlowManager.process_packet()` or offline flow extraction to produce `Flow` objects.
3. **Map:** For each flow, look up the 5-tuple + timestamp in the traffic generator log to assign the label.
4. **Validate:** Any flow not found in the generator log is discarded (unlabeled).
5. **Persist:** Save labeled flows as a structured dataset (CSV/JSON) with all 18 features + ground-truth label.

### 4.3 Labeling Rules
- A flow is **PORT_SCAN** only if the generator explicitly scanned ≥10 unique ports from the source IP within the 10-second window.
- A flow is **BRUTE_FORCE** only if the generator made ≥10 connection attempts to the same service.
- A flow is **DOS** only if the generator produced sustained high rate per the DOS thresholds.
- A flow is **RECONNAISSANCE** only if the generator contacted ≥5 unique IPs or ≥10 unique ports across targets.
- A flow is **BENIGN** only if it was generated by a known benign application with no attack generator active.
- **Ambiguous flows** (e.g., a TCP connection during a scan window but not part of the scan) are **excluded**, not forced into a class.

### 4.4 Contamination Prevention
- **Temporal separation:** Benign and attack collection windows are separated by ≥5 minutes with no traffic.
- **Network separation:** Attack traffic uses a dedicated target VM; benign traffic uses different source IPs or different time windows.
- **Source IP separation:** Attack source IPs are distinct from benign source IPs.
- **Window tagging:** Each flow is tagged with its collection session ID; sessions are split, not randomly shuffled.

---

## 5. DATASET SIZE

### 5.1 Statistical Reasoning

The current CICIDS2017 clean dataset has:
- BENIGN: 19,198
- PORT_SCAN: 323
- BRUTE_FORCE: 3,658
- DOS: 17,595
- RECONNAISSANCE: 36

The RECONNAISSANCE class is the bottleneck. With 36 samples, the confidence interval for recall is extremely wide.

**Minimum recommended flows per class:**

| Class | Minimum | Rationale |
|-------|---------|-----------|
| BENIGN | 2,000 | Must cover protocol diversity (TCP, UDP, ICMP, DNS) and capture realistic variance. 2,000 gives ±1.4% CI at 95% for benign rate estimates. |
| PORT_SCAN | 500 | Current cleaned PORT_SCAN is 323. 500 ensures stable F1 estimation and matches the reduced class size after deduplication. |
| BRUTE_FORCE | 500 | Current cleaned is 3,658. 500 is sufficient for stable metrics; more is better but diminishing returns. |
| DOS | 1,000 | Current cleaned is 17,595. 1,000 captures variance across attack tools and rates. |
| RECONNAISSANCE | 500 | **Critical.** Current cleaned is 36. 500 is the minimum to get a meaningful F1 CI (±4.4% at 95%). |

**Total minimum dataset: ~4,500 flows.**

### 5.2 Why Not 500+500 Blindly?
- 500 per class is insufficient for BENIGN, which must cover multiple protocols, interfaces, and applications to be representative.
- RECONNAISSANCE needs 500+ because its current F1 has a 95% CI of roughly ±0.12 (based on 36 samples). With 500 samples, CI shrinks to ±0.04.
- DOS and BRUTE_FORCE benefit from 1,000+ because attack tools produce varying feature distributions (hping3 vs nping vs custom scripts).

### 5.3 Stratification Requirement
The evaluation dataset must maintain the class distribution observed in the target deployment environment. If the deployment is on loopback with rare attacks, the test set should reflect that skew rather than forcing 50/50 balance.

---

## 6. COLLECTION METHODOLOGY

### 6.1 Collection Sessions
Each collection session produces one labeled dataset file:
- `benign_loopback_tcp_001.pcap`
- `attack_dos_hping3_001.pcap`
- etc.

Each session includes:
- Start/end timestamps
- Interface name
- Source IP(s)
- Target IP(s)
- Traffic generator command/script
- Generator log (stdout/stderr)
- Session metadata JSON

### 6.2 Benign Collection Protocol
1. **Loopback baseline:** Capture 10 minutes of idle loopback traffic → label as BENIGN (no flows expected, validates no false positives from silence).
2. **Loopback active:** Run benign generators (ping, TCP connects, UDP sends, DNS queries) for 10 minutes → label as BENIGN.
3. **Local services:** Start `python -m http.server 8080`, `nc -l 22`, etc. Generate client traffic for 5 minutes → label as BENIGN.
4. **Host-only lab:** Capture 30 minutes of normal workstation traffic on `192.168.56.x` → label as BENIGN (heuristic: exclude flows matching attack signatures).
5. **Application traffic:** Capture 30 minutes of browser/IDE/chat traffic → label as BENIGN.

### 6.3 Attack Collection Protocol
1. **PORT_SCAN:** Run `nmap -sS --top-ports 100 192.168.56.101` from Kali VM. Capture 2 minutes (scan + fallout). Label flows with ≥10 unique dst ports as PORT_SCAN.
2. **BRUTE_FORCE:** Run `hydra -l admin -P /usr/share/wordlists/fasttrack.txt ssh://192.168.56.101` from Kali VM. Capture 2 minutes. Label flows to port 22 with repeated connections as BRUTE_FORCE.
3. **DOS:** Run `hping3 -S --flood -p 80 192.168.56.101` for 30 seconds. Capture 1 minute. Label high-rate flows as DOS.
4. **RECONNAISSANCE:** Run `nmap -sL 192.168.56.0/24` from Kali VM. Capture 2 minutes. Label flows with ≥5 unique dst IPs as RECONNAISSANCE.

### 6.4 Feature Extraction from Captured Traffic
Use the existing `FlowManager` and `Flow` classes to extract the canonical 18 features from each pcap. This ensures the evaluation dataset is directly compatible with the trained model.

```python
# Pseudocode — NOT production code
fm = FlowManager(flow_timeout=10.0)
for packet in rdpcap(pcap_path):
    flows = fm.process_packet(packet)
    for flow in flows:
        features = flow.get_features()
        label = lookup_label_from_generator_log(flow)
        save_labeled_flow(features, label, flow)
```

---

## 7. LEAKAGE PREVENTION

### 7.1 Split Strategy
**DO NOT use random shuffling.** Use **session-based splitting**:

1. **Collection-session separation:** Each attack tool invocation is a separate session. Sessions are the atomic unit of splitting.
2. **Time-based holdout:** The first 70% of sessions (by start time) form the training/evaluation set; the final 30% form the **temporal holdout test set**.
3. **Source IP separation:** For cross-flow attacks (PORT_SCAN, BRUTE_FORCE, RECONNAISSANCE), ensure that the source IPs in the holdout set are disjoint from the training set.

### 7.2 Deduplication
- Remove exact-duplicate feature vectors within each split.
- Do NOT remove near-duplicates across splits (they may represent genuine attack patterns).

### 7.3 No Data Leakage Checklist
- [ ] Test set sessions start after training set sessions end.
- [ ] No source IP overlap for cross-flow attack classes.
- [ ] No exact-duplicate feature vectors in test set.
- [ ] Scaler is fit ONLY on the training set.
- [ ] No pcap files are shared between splits.

---

## 8. METRICS

### 8.1 Classification Metrics
| Metric | Definition |
|--------|-----------|
| Accuracy | (TP+TN)/(TP+TN+FP+FN) across all classes |
| Macro Precision | Unweighted mean of per-class precision |
| Macro Recall | Unweighted mean of per-class recall |
| Macro F1 | Unweighted mean of per-class F1 |
| Weighted Precision | Support-weighted mean precision |
| Weighted Recall | Support-weighted mean recall |
| Weighted F1 | Support-weighted mean F1 |
| Confusion Matrix | 5×5 matrix of predicted vs actual |
| Per-class support | Number of true samples per class |
| False Positive Rate (FPR) | FP / (FP + TN) per class |
| False Negative Rate (FNR) | FN / (FN + TP) per class |

### 8.2 Operational Metrics
| Metric | Definition |
|--------|-----------|
| Alerts per hour | Total alerts / capture duration (hours) |
| False alerts per hour | Alerts with incorrect attack_type / hour |
| Detection latency | Time from first packet of attack flow to alert generation |
| Flow processing failures | Count of flows where pipeline raised exception |
| Dropped packets | Queue overflow count (`queue.Full` in capture callback) |
| Flow timeout accuracy | Flows closed by timeout vs explicit close |

### 8.3 Correlation-Specific Metrics
| Metric | Definition |
|--------|-----------|
| Agreement rate | Fraction of alerts where Rule + ML agree |
| Rule-only rate | Fraction where only Rule Engine detected attack |
| ML-only rate | Fraction where only ML detected attack |
| Disagreement rate | Fraction where both detected but different classes |

---

## 9. LOOPBACK STRATEGY

### 9.1 Current State
- **FACT:** The model was trained on zero loopback traffic.
- **FACT:** Stage 9 tests confirm the pipeline captures loopback traffic without crashes.
- **FACT:** The Rule Engine has loopback guards for PORT_SCAN and RECONNAISSANCE cross-flow checks.
- **FACT:** No labeled loopback dataset exists.

### 9.2 Key Questions
1. **Should loopback be part of the production ML domain?**
   - **INFERENCE:** The production environment may include loopback traffic (local services, IPC, health checks). If the NIDS is deployed on a host that captures all interfaces, loopback flows will reach the ML model.
   - **RECOMMENDATION:** Loopback **must** be evaluated before production deployment. The model should not be deployed on loopback traffic without validation.

2. **Should loopback be excluded?**
   - **INFERENCE:** Excluding loopback requires a BPF filter or interface-level separation. This is operationally simple but may miss attacks that use loopback (e.g., localhost-only services).
   - **RECOMMENDATION:** Exclusion is acceptable as a **short-term mitigation** if evaluation is not yet complete. The NIDS should document which interfaces are monitored.

3. **Should it have a separate model/domain?**
   - **INFERENCE:** Loopback traffic has fundamentally different feature distributions (short durations, small packets, high SYN ratios for local connections). A separate model could be more accurate.
   - **RECOMMENDATION:** **Do not build a separate model yet.** First evaluate the current model on loopback data. If FPR is unacceptable, then consider a domain-specific model.

### 9.3 Evidence Required
Before deciding on loopback treatment, the following must be measured:
1. **False Positive Rate:** How many benign loopback flows are classified as attack?
2. **False Negative Rate:** How many malicious loopback flows evade detection?
3. **Feature Distribution Shift:** Wasserstein distance between CICIDS2017 features and loopback features for each class.
4. **Calibration:** Are ML probabilities meaningful for loopback flows?

---

## 10. ACCEPTANCE CRITERIA

### 10.1 Deployment Gate (All Must Pass)
| Criterion | Threshold | Rationale |
|-----------|-----------|-----------|
| Macro F1 (clean holdout) | ≥ 0.90 | Matches Stage 11.1 baseline |
| Macro F1 (temporal holdout) | ≥ 0.85 | Allows some generalization gap |
| BENIGN False Positive Rate | ≤ 2% | Acceptable alert fatigue level |
| DOS Recall | ≥ 0.90 | Critical attack class |
| PORT_SCAN Recall | ≥ 0.85 | Moderate criticality |
| BRUTE_FORCE Recall | ≥ 0.80 | Moderate criticality |
| RECONNAISSANCE Recall | ≥ 0.60 | Data-starved; lower bar |
| Flow processing failure rate | ≤ 0.1% | Pipeline reliability |
| Detection latency (p95) | ≤ 5s | Operational responsiveness |

### 10.2 Threshold Derivation
- **FPR ≤ 2%:** Based on typical SOC alert-handling capacity. >2% FPR on benign traffic would generate >1 false alert per minute on a busy host, which is unsustainable.
- **Macro F1 ≥ 0.85 on temporal holdout:** Allows for realistic distribution shift while maintaining overall utility.
- **RECONNAISSANCE Recall ≥ 0.60:** Current clean holdout is 0.71. A drop to 0.60 on new data is acceptable given the class's data scarcity.
- **Latency ≤ 5s:** Derived from the 10-second flow timeout. Alerts should be generated before the next timeout cycle.

---

## 11. RISKS

### 11.1 Statistical Risks
- **RECONNAISSANCE class:** Even with 500 samples, the confidence interval for recall is ±4.4%. This means a measured recall of 0.60 could be as low as 0.556 or as high as 0.644.
- **Temporal holdout size:** 30% of sessions may yield few attack samples if attacks are rare in the collection schedule.

### 11.2 Operational Risks
- **Loopback capture:** On Windows, loopback capture may require Npcap/WinPcap with appropriate permissions. Capture failures would bias the dataset.
- **Attack tool availability:** Kali Linux tools (nmap, hydra, hping3) must be installed and accessible.
- **Network isolation:** Attack traffic must not leak to production networks.

### 11.3 ML-Specific Risks
- **Feature distribution shift:** Loopback flows have vastly different `duration`, `packets_per_second`, and `bytes_per_second` distributions than CICIDS2017.
- **Model overfitting:** The Random Forest may have memorized CICIDS2017-specific artifacts (e.g., specific packet-size distributions).
- **Calibration breakdown:** Probabilities calibrated on CICIDS2017 may be meaningless for loopback traffic.

---

## 12. RECOMMENDED NEXT STEP

### RECOMMENDATION: C. BUILD AN EVALUATION HARNESS FIRST

**Rationale:**
1. The current test infrastructure (`test_stage9_live.py`) captures traffic but does not persist labeled flows or compute ML-level accuracy.
2. Attack traffic generation scripts do not exist yet; they must be created in a controlled, reproducible manner.
3. The evaluation harness must automate: capture → flow extraction → labeling → metric computation → report generation.
4. Building the harness before collecting data ensures that collection is **purpose-driven** rather than ad-hoc.

**Specific next actions:**
1. Create `NIDS/evaluation/collect_loopback.py` — automates benign loopback traffic generation and labeled flow extraction.
2. Create `NIDS/evaluation/collect_attacks.py` — automates controlled attack traffic generation against a dedicated target VM.
3. Create `NIDS/evaluation/evaluate.py` — loads labeled flow datasets, runs the trained model, computes all metrics, and produces the comparison report.
4. Create `NIDS/evaluation/ground_truth.py` — defines the labeling protocol and contamination-prevention checks.
5. Document the lab topology: Kali attacker VM, target victim VM, Windows host, interfaces, IP scheme.

**Do NOT:**
- Generate attack traffic yet.
- Modify production code.
- Retrain the model.
- Change thresholds.

---

## APPENDIX: EXISTING TEST CAPABILITIES SUMMARY

| Capability | Location | Status |
|------------|----------|--------|
| Live packet capture | `NIDS/packet_capture.py` | Implemented |
| Flow extraction | `NIDS/flow_manager.py` | Implemented |
| 18-feature vector | `NIDS/flow.py` | Implemented |
| ML inference | `NIDS/model.py` | Implemented |
| Rule detection | `NIDS/rule_engine.py` | Implemented |
| Correlation | `NIDS/correlator.py` | Implemented |
| Alert generation | `NIDS/alerts.py` | Implemented |
| Dashboard aggregation | `NIDS/dashboard_data.py` | Implemented |
| Benign loopback generators | `NIDS/tests/test_stage9_live.py` | Implemented |
| Attack generators | None | **MISSING** |
| Labeled loopback dataset | None | **MISSING** |
| Evaluation harness | `NIDS/evaluation/stage11_1_leakage_free.py` | Implemented (IID only) |
| Real-world evaluation harness | None | **MISSING** |

---

**FACT:** The pipeline can capture and process loopback traffic.
**INFERENCE:** The ML model's behavior on loopback is unvalidated.
**RECOMMENDATION:** Build a purpose-built evaluation harness before collecting any real-world data.

---

**STAGE 11.2 VERDICT: YELLOW**

The design is sound and complete, but execution requires building the evaluation harness and collecting new labeled data. No production changes are warranted until the harness produces measurable results.
