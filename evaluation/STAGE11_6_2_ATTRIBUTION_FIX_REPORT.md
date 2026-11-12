# STAGE 11.6.2 — ATTRIBUTION FIX AND VERIFICATION

## Executive Summary

Stage 11.6.1 identified a HIGH-severity correctness bug in the attribution logic: flows were matched using only `dst_port + protocol + timestamp`, enabling false attribution of background DNS traffic (`53 -> 51604`) as controlled benign traffic.

This report documents the fix, which introduces source-port semantics (`EXACT`, `EPHEMERAL`, `ANY`) and a `_validate_source_port()` helper that rejects well-known source ports (`0-1023`) for `EPHEMERAL` mode. The DNS generator was also changed from `EXACT` to `EPHEMERAL` to match actual outbound traffic patterns.

**Verdict: GREEN — All regression tests pass; DNS false attribution is provably rejected; TCP/UDP matching uses explicit source-port semantics; timestamp matching uses actual flow timing.**

---

## 1. Bug Description (from Stage 11.6.1)

The original `_match_flow_to_generation_by_5tuple` accepted any flow whose:
- `dst_ip` matched the generation event destination,
- `dst_port` matched the generation event `dst_port`,
- `protocol` matched the generation event `expected_protocol`,
- `timestamp` fell within a loose window,

regardless of `src_port`.

**Consequence:** A background DNS response from port `53` to our listener on port `51604` was incorrectly attributed as controlled benign DNS traffic, inflating the DNS capture count by 1 and introducing contamination into the evaluation dataset.

---

## 2. Fix Design

### 2.1 Source-Port Semantics

Three modes were added to `ControlledCollector`:

| Mode | Constant | Validation Rule |
|------|----------|-----------------|
| `EXACT` | `SOURCE_PORT_MODE_EXACT` | Flow `src_port` must exactly equal the generation event `src_port`. |
| `EPHEMERAL` | `SOURCE_PORT_MODE_EPHEMERAL` | Flow `src_port` must be `> 1023` (not a well-known port). |
| `ANY` | `SOURCE_PORT_MODE_ANY` | Any `src_port` is accepted. |

### 2.2 Helper Function

```python
def _validate_source_port(flow_src_port, mode, expected_src_port):
    if mode == SOURCE_PORT_MODE_EXACT:
        return flow_src_port == expected_src_port, ...
    elif mode == SOURCE_PORT_MODE_EPHEMERAL:
        if flow_src_port is None or flow_src_port <= 1023:
            return False, f"Source port {flow_src_port} is not ephemeral"
        return True, ...
    elif mode == SOURCE_PORT_MODE_ANY:
        return True, ...
    else:
        return False, f"Unknown source_port_mode: {mode}"
```

### 2.3 Integration into Attribution Logic

The `_match_flow_to_generation_by_5tuple` method now:
1. Checks `src_ip` match (unchanged).
2. Calls `_validate_source_port(flow.src_port, event.source_port_mode, event.source_port)`.
3. If validation fails, returns `UNATTRIBUTED` immediately.
4. Proceeds with `dst_port`, `protocol`, and `timestamp` checks.

### 2.4 Generator Changes

The DNS generator in `collect_controlled_11_6.py` was changed from `SOURCE_PORT_MODE_EXACT` with a fixed `src_port` to `SOURCE_PORT_MODE_EPHEMERAL` with `src_port=None`, reflecting that DNS queries originate from random ephemeral client ports.

---

## 3. Regression Tests (Tests A–G)

| Test | Description | Expected | Result |
|------|-------------|----------|--------|
| A | DNS background traffic (`53 -> 51604`) | `!= ATTRIBUTED` | PASS |
| B | Ephemeral source port to expected dst | `== ATTRIBUTED` | PASS |
| C | `EXACT` source port match | `== ATTRIBUTED` | PASS |
| D | `EXACT` source port mismatch | `!= ATTRIBUTED` | PASS |
| E | Timestamp outside window | `!= ATTRIBUTED` | PASS |
| F | Dst port match but protocol differs | `== CONTAMINATED` | PASS |
| G | ICMP to wrong destination | `!= ATTRIBUTED` | PASS |

Additional unit tests verify `_validate_source_port` behavior for all three modes.

---

## 4. Verification Results

### 4.1 Attribution Regression Tests

```
PASS: Test A - DNS false attribution rejected
PASS: Test B - Ephemeral source port attributed
PASS: Test C - EXACT source port match attributed
PASS: Test D - EXACT source port mismatch rejected
PASS: Test E - Timestamp outside window rejected
PASS: Test F - Protocol mismatch is CONTAMINATED
PASS: Test G - ICMP to wrong destination not attributed
PASS: Source port EXACT validation
PASS: Source port EPHEMERAL validation
PASS: Source port ANY validation

All attribution regression tests passed.
```

### 4.2 Evaluation Harness Tests

```
EVALUATION TESTS: 24/24 passed, 0 failed
```

### 4.3 Full Regression Suite

```
Overall: ALL PASSED
```

### 4.4 Stage 10 Focused Tests

```
Overall: ALL PASSED
```

### 4.5 Stage 9 Live Tests

```
Overall: ALL PASSED (22/22)
```

---

## 5. Controlled Collection Results (Stage 11.6.2)

| Category | TCP | UDP | DNS | ICMP | Total |
|----------|-----|-----|-----|------|-------|
| Attributed | 19 | 19 | 0 | 1 | 39 |
| Unattributed | 0 | 0 | 0 | 0 | 0 |
| Contaminated | 0 | 0 | 0 | 0 | 0 |

**Notes:**
- DNS collection returns 0 attributed flows because the loopback interface does not reliably deliver DNS queries to our custom listener in the Windows environment. Attribution for DNS remains unsupported in this environment.
- ICMP attribution is limited to 1 flow; broader ICMP collection is unreliable due to OS-level loopback filtering.

---

## 6. Remaining Limitations

1. **DNS collection unreliable on Windows loopback.** The custom DNS listener on port 51200 does not receive queries generated by standard system resolvers. Attribution logic is correct, but collection infrastructure is insufficient.
2. **ICMP collection limited.** Only 1 ICMP flow was successfully attributed. Background ICMP traffic is filtered by the OS.
3. **Evaluation dataset size is small (39 flows).** Sufficient for regression testing and FPR estimation, but insufficient for robust ML accuracy evaluation.

---

## 7. Stop Condition

**Do not begin Stage 11.7 (attack collection) or expand benign collection until this Stage 11.6.2 report is reviewed and approved.**

If approved, the next step is to design Stage 11.7 attack collection with the same controlled-attribution approach, using dedicated ports and source-port validation for each attack category.

---

## 8. Files Modified

- `NIDS/evaluation/collect_controlled_11_6.py` — Added source-port semantics, `_validate_source_port()`, and updated attribution logic. Changed DNS generator to `EPHEMERAL` mode.
- `NIDS/tests/test_attribution_regression.py` — Rewrote all tests to use positional arguments matching the fixed `_match_flow_to_generation_by_5tuple` signature. Added 10 regression tests (A–G + 3 validation unit tests).

## 9. Files Unchanged (Production Code)

No production code (`NIDS/pipeline.py`, `NIDS/model.py`, `NIDS/rules.py`, etc.) was modified.
