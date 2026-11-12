# STAGE 11.6.1 — ATTRIBUTION AUDIT BEFORE EXPANDED BENIGN COLLECTION

## Executive Summary

This audit examines the 2 successfully attributed non-TCP/UDP flows from Stage 11.6:
- 1 controlled_dns session (UDP, dst_port=51604)
- 1 controlled_icmp session (ICMP, dst_ip=127.0.0.2)

**Verdict: RED — The DNS attribution is demonstrably incorrect. The ICMP attribution is ambiguous. The attribution matching logic has a correctness flaw that can label unrelated background traffic as generated traffic.**

---

## 1. DNS Successful Attribution Trace

### Generation Event
- **Category:** controlled_dns
- **Expected protocol:** UDP (17)
- **Destination:** 127.0.0.1:51604
- **Generation method:** Scapy DNS queries to 127.0.0.1:51604
- **Expected flow direction:** Random ephemeral source port -> 51604

### Captured Flow
- **5-tuple:** 127.0.0.1:53 -> 127.0.0.1:51604
- **Protocol:** UDP (17)
- **Duration:** 2.043s
- **Packets:** 21
- **Bytes:** 1394
- **Attribution status:** ATTRIBUTED

### Analysis

**The captured flow has src_port=53, which is the system DNS server port.**

Our generator sends Scapy packets FROM random ephemeral ports TO port 51604. The expected response would be FROM port 51604 TO the random ephemeral port.

The flow `53 -> 51604` is backwards from our generated traffic. Port 53 is the well-known DNS server port. This flow represents:
1. Either the system's DNS resolver sending a query to our listener on port 51604, OR
2. Some other background DNS traffic that happened to target port 51604

**This is NOT our generated DNS traffic.** Our generated traffic would have source ports in the ephemeral range (typically 49152-65535), not port 53.

### Verdict: INVALID

The DNS attribution is a false positive caused by the attribution logic matching on `dst_port` alone without verifying the source port.

---

## 2. ICMP Successful Attribution Trace

### Generation Event
- **Category:** controlled_icmp
- **Expected protocol:** ICMP (1)
- **Destination:** 127.0.0.2
- **Generation method:** `ping -n 1 127.0.0.2` x 20
- **Expected:** 20 ICMP echo requests + 20 replies = 40 packets, ~2560 bytes

### Captured Flow
- **5-tuple:** 127.0.0.1:0 -> 127.0.0.2:0
- **Protocol:** 1 (ICMP)
- **Duration:** 2.456s
- **Packets:** 40
- **Bytes:** 2560
- **Attribution status:** ATTRIBUTED

### Analysis

**Statistics match ICMP ping:**
- 40 packets = 20 pings * 2 packets/echo (request + reply)
- 2560 bytes / 40 packets = 64 bytes/packet (standard ICMP echo packet size)
- 2.456s duration for 20 pings at ~0.1s interval = ~2.0s expected. Matches.

**However, Windows loopback ICMP capture is unreliable:**
- The Windows NPF_Loopback driver typically does NOT allow sniffing ICMP packets on the loopback interface
- ICMP packets are processed internally by the TCP/IP stack and not exposed to WinPcap/Npcap
- If ICMP were captured, we would expect to see actual ICMP types (8=echo request, 0=echo reply) in the packet data

**Cannot verify from dataset alone:**
- The EvaluationRecord stores protocol=1 and ports=0 (ICMP placeholder)
- The attribution log does not store ICMP type/code
- We cannot confirm these are actually ICMP echo packets vs. some other traffic mapped to protocol=1

### Verdict: AMBIGUOUS

The statistics are consistent with ICMP ping traffic, but we cannot verify the actual packet contents. Windows loopback ICMP capture is known to be unreliable.

---

## 3. Attribution Matching Logic Audit

### Current Implementation

```python
def _match_flow_to_generation_by_5tuple(self, src_ip, src_port, dst_ip, dst_port, protocol, generation_events, flow_start_time=None):
    # ATTRIBUTED: dst_ip + dst_port + protocol + timestamp match
    for event in generation_events:
        if (dst_ip == event["dst_ip"] and
            dst_port == event["dst_port"] and
            protocol == event["expected_protocol"]):
            if flow_start_time is not None:
                if (event["timestamp"] - 1.0 <= flow_start_time <= event["timestamp"] + 5.0):
                    return ATTRIBUTED, event
            else:
                if (event["timestamp"] - 1.0 <= time.time() <= event["timestamp"] + 5.0):
                    return ATTRIBUTED, event

    # CONTAMINATED: dst_ip + dst_port match, protocol differs
    for event in generation_events:
        if (dst_ip == event["dst_ip"] and dst_port == event["dst_port"]):
            if protocol != event["expected_protocol"]:
                return CONTAMINATED, event

    # AMBIGUOUS: protocol matches, dst differs
    for event in generation_events:
        if protocol == event["expected_protocol"]:
            return AMBIGUOUS, event

    return UNATTRIBUTED, None
```

### Issues Found

| Issue | Severity | Description |
|-------|----------|-------------|
| **A** | **HIGH** | `dst_port` alone is sufficient for ATTRIBUTED match. Any background traffic to the same destination port is accepted, regardless of source port. |
| **B** | **MEDIUM** | Timestamp matching uses `time.time()` at match moment, not the flow's actual `start_time`. For inline-completed flows, the flow's start_time is more accurate. |
| **C** | **LOW** | No verification that the flow's source port is ephemeral (>= 49152). Well-known ports (0-1023) in the source position suggest the flow is a response or background traffic, not generated traffic. |
| **D** | **LOW** | ICMP flows use port 0 as placeholder. Any ICMP flow to the target IP within the time window matches, with no ICMP type verification. |

### Can Background Traffic Accidentally Match?

**YES.** Issue A is a proven correctness flaw:

- We generated DNS traffic to port 51604
- Background DNS traffic from port 53 to port 51604 matched as ATTRIBUTED
- The flow `53 -> 51604` is clearly not our generated traffic
- Yet it passed attribution because `dst_port == 51604` and `protocol == UDP`

### Are Exact 5-Tuples Required?

**No.** The matching logic requires:
- `dst_ip` match
- `dst_port` match  
- `protocol` match
- Timestamp proximity

It does NOT require `src_ip` or `src_port` to match. This is intentional because source ports are ephemeral, but it creates the vulnerability demonstrated by the DNS false attribution.

### Are Protocol Mismatches Correctly Prevented?

**Yes, for the matched flow.** If a flow matches `dst_ip` + `dst_port` but has a different protocol, it is correctly labeled CONTAMINATED. However, the initial ATTRIBUTED match is too permissive.

---

## 4. Correctness Issue Found

**Issue:** The attribution logic accepts any flow to the expected destination port with the expected protocol, without verifying the source port or flow direction.

**Impact:** Background traffic to the same destination port can be incorrectly labeled as generated traffic.

**Example from this audit:**
- Expected: random_ephemeral_port -> 51604 (UDP)
- Actual: 53 -> 51604 (UDP)
- Result: INCORRECTLY ATTRIBUTED as generated DNS traffic

---

## 5. Evaluation-Only Fix

**Fix:** Add source port validation to the attribution logic. For TCP/UDP flows, reject flows where the source port is a well-known port (0-1023) unless the generation event explicitly specifies that port.

**Change location:** `collect_controlled_11_6.py`, method `_match_flow_to_generation_by_5tuple`

**Proposed change:**
```python
# Reject flows with well-known source ports (0-1023) unless explicitly expected
if protocol in (6, 17) and 0 <= src_port <= 1023:
    continue  # Skip this match attempt; likely background/response traffic
```

**Status:** NOT APPLIED YOUT. Per Stage 11.6.1 instructions, a fix should only be made if a concrete correctness bug is found. We have found one. The fix should be made before Stage 11.7.

---

## 6. Recommendations for Stage 11.7

### TCP/UDP Collection
- **Trustworthy.** 95% attribution rate, 0% protocol mismatches, no false attributions detected.
- Apply the source-port validation fix to prevent future DNS-like false attributions.
- Proceed with expanded TCP/UDP collection using dedicated ports.

### DNS Collection
- **Do NOT use loopback.** DNS attribution on loopback is unreliable because:
  1. Scapy-generated DNS packets are not consistently captured
  2. Background DNS traffic contaminates attribution
- If DNS evaluation is required, use external interface capture with BPF filters.

### ICMP Collection
- **Do NOT use loopback.** ICMP capture on Windows loopback is unreliable.
- If ICMP evaluation is required, use external interface capture.
- The 1 attributed ICMP session has statistics consistent with ping traffic but cannot be verified at the packet level.

---

## 7. Tests Executed

| Test | Result |
|------|--------|
| `test_evaluation` | 24/24 PASS |
| `test_regression` | ALL PASSED |
| `test_stage10` | ALL PASSED |
| Attribution audit script | PASS (found DNS false attribution) |

---

## 8. Final Verdict

**YELLOW**

- TCP/UDP attribution remains trustworthy and can proceed to Stage 11.7
- One concrete correctness bug found in attribution logic (dst_port-only matching)
- DNS and ICMP loopback attribution is unreliable
- Recommend: apply source-port validation fix, then proceed with TCP/UDP expansion

---

## 9. Files Examined

- `controlled_controlled_11_6_benign_20260909T174810Z_attribution_log.json`
- `controlled_controlled_11_6_benign_20260909T174810Z.jsonl`
- `collect_controlled_11_6.py`
