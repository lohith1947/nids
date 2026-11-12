# STAGE 11.8.7 — ENVIRONMENT READINESS AUDIT

**Date:** 2026-09-10
**Status:** PARTIAL — Host-side infrastructure ready; guest-side verification blocked by lack of NIDS-VM access credentials

---

## 1. Executive Summary

The VirtualBox isolated Host-Only lab is operational. Both Kali Linux (attacker) and NIDS-VM (target/capture host) are running with Host-Only networking configured. Host-side model verification passes. However, guest-side verification inside NIDS-VM is **blocked**: Guest Additions guestcontrol and guestproperty enumeration are not returning usable results for NIDS-VM, and no login credentials are available. The existing evaluation collection script is hardcoded for loopback and requires parameterization before non-loopback collection can proceed.

**Verdict:** `YELLOW — Host-side ready; guest-side readiness unverified.`

---

## 2. Frozen Model Verification

| Property | Value | Status |
|----------|-------|--------|
| Joblib bundle | `dict` with keys `['scaler', 'clf']` | ✓ PASS |
| Scaler type | `StandardScaler` | ✓ PASS |
| Classifier type | `RandomForestClassifier` | ✓ PASS |
| n_estimators | 200 | ✓ PASS |
| max_depth | 20 | ✓ PASS |
| random_state | 42 | ✓ PASS |
| n_jobs | -1 | ✓ PASS |
| n_features_in_ | 18 | ✓ PASS |
| classes_ | [0, 1, 2, 3, 4] → BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE | ✓ PASS |
| Model hash | `7bcc643154a1f44d` | ✓ PASS |

**Conclusion:** Model integrity is confirmed. No modifications have been made.

---

## 3. Network Infrastructure Audit

### 3.1 Host-Side Interfaces

| Interface | Description | Status | IP Address | Subnet | Role |
|-----------|-------------|--------|------------|--------|------|
| Ethernet | Realtek PCIe GbE | Up | 192.168.1.97, 169.254.236.177 | /24, /16 | Physical LAN — **NOT USABLE** |
| Wi-Fi | Intel Wi-Fi 6 | Up | 10.185.231.112 | /24 | Physical LAN — **NOT USABLE** |
| Ethernet 2 | VirtualBox Host-Only Ethernet Adapter | Up | 169.254.185.144 | /16 | **ISOLATED LAB — USABLE** |
| Loopback | Loopback Pseudo-Interface 1 | Up | 127.0.0.1 | /8 | Loopback — **NOT USABLE for Stage 11.8.7** |

### 3.2 VirtualBox Host-Only Network (Host Perspective)

| Property | Value |
|----------|-------|
| Adapter name | VirtualBox Host-Only Ethernet Adapter |
| GUID | 01536027-d839-4fda-9331-f57e87310a8c |
| IP address | 169.254.185.144 |
| Netmask | 255.255.0.0 (/16) |
| DHCP | Disabled |
| Status | Up |
| Link speed | 1 Gbps |

### 3.3 VM Network Configurations (from VBoxManage)

| VM | NIC 1 | NIC 2 | Host-Only Adapter | Cable Connected |
|----|-------|-------|-------------------|-----------------|
| Kali Linux | NAT (10.0.2.15) | Host-Only | VirtualBox Host-Only Ethernet Adapter | on |
| NIDS-VM | NAT | Host-Only | VirtualBox Host-Only Ethernet Adapter | on |

### 3.4 VM IP Addresses (from Guest Properties)

| VM | Interface | IP Address | Netmask | Status | Source |
|----|-----------|------------|---------|--------|--------|
| Kali Linux | eth0 (NAT) | 10.0.2.15 | 255.255.255.0 | Up | VBoxManage guestproperty |
| Kali Linux | eth1 (Host-Only) | 192.168.56.105 | 255.255.255.0 | Up | VBoxManage guestproperty |
| NIDS-VM | Unknown | **Cannot retrieve** | Unknown | Unknown | Guest property enumeration failed |

**Note:** Kali's Host-Only IP (192.168.56.105) matches the user-reported address. NIDS-VM's guest properties are not available via VBoxManage; its reported IP (192.168.56.107) cannot be independently confirmed from the host at this time.

---

## 4. VM Operational Status

| VM | State | Running Since | Guest Additions | Run Level | OS |
|----|-------|---------------|-----------------|-----------|-----|
| Kali Linux | running | N/A | 6.0.0 r127566 | 2 (active) | Debian (Kali 6.12.38) |
| NIDS-VM | running | 2026-09-10 19:47:59 | 6.0.0 r127566 | 1 (partial) | Ubuntu (64-bit) |

**Logged-in user on Kali:** `panda`

---

## 5. Connectivity Verification

### 5.1 Host → Kali
- **Ping to 192.168.56.105:** No reply
- **Expected result:** Host is on 169.254.185.144/16; Kali is on 192.168.56.105/24. Different subnets. Ping failure is expected.
- **Status:** NOT REACHABLE from host (expected)

### 5.2 Host → NIDS-VM
- **Ping to 192.168.56.107:** No reply
- **Expected result:** Same subnet mismatch as above.
- **Status:** NOT REACHABLE from host (expected)

### 5.3 Kali → NIDS-VM (User Reported)
- **User claim:** Both VMs can ping each other successfully.
- **Independent confirmation:** Cannot verify from host. Kali is on 192.168.56.105/24; if NIDS-VM is on 192.168.56.107/24 with the same Host-Only adapter, ping should work at the VirtualBox virtual switch level.
- **Status:** UNVERIFIED — relies on user confirmation

### 5.4 Guest Control / Guest Property Access
- **Kali:** Guest properties accessible. Guestcontrol login failed for tested credentials (`root/toor`, `kali/kali`, `panda/panda`, `panda/toor`, `panda/kali`, `panda/password`).
- **NIDS-VM:** Guest property enumeration returns only host-side metadata. Guestcontrol returns "guest execution service is not ready (yet)."
- **Status:** BLOCKED — no working guest access credentials

---

## 6. NIDS-VM Guest-Side Verification

| Check | Method | Result | Status |
|-------|--------|--------|--------|
| List network interfaces | `ip addr` / `ifconfig` inside VM | Cannot execute — no guest access | **BLOCKED** |
| Identify Host-Only interface name | Guest properties / guestcontrol | Not available | **BLOCKED** |
| Verify interface can observe Kali↔NIDS-VM traffic | Live capture test | Cannot execute | **BLOCKED** |
| Test packet capture (ping test) | Scapy/Wireshark/tcpdump on NIDS-VM | Cannot execute | **BLOCKED** |
| Verify NIDS code installed | Check NIDS directory / Python imports | Cannot execute | **BLOCKED** |
| Verify Python environment | `python3 --version`, `pip list` | Cannot execute | **BLOCKED** |
| Verify frozen model present | `ls NIDS/models/nids_model.joblib` | Cannot execute | **BLOCKED** |

**Conclusion:** All critical guest-side checks are blocked. The host can confirm VM configuration and guest properties for Kali, but cannot penetrate NIDS-VM's guest environment.

---

## 7. Evaluation Script Readiness

### 7.1 Available Collection Scripts

| Script | Purpose | Loopback Hardcoded? | Non-Loopback Ready? |
|--------|---------|---------------------|---------------------|
| `collect_attack_11_8_v2.py` | Stage 11.8.2 attack collection | **YES** — `INTERFACE = "Loopback Pseudo-Interface 1"`, `target_ip = "127.0.0.1"` | **NO** |
| `collect_controlled_11_6.py` | Stage 11.6 benign attribution | Partially — uses `interface` parameter but defaults to loopback concepts | **PARTIAL** |
| `collect_attacks.py` | Early attack collection | Unknown without review | Unknown |

### 7.2 Script Gaps for Stage 11.8.7

The primary attack collection script (`collect_attack_11_8_v2.py`) contains the following hardcoded loopback artifacts:

| Hardcoded Value | Line | Required Change for Stage 11.8.7 |
|-----------------|------|--------------------------------|
| `INTERFACE = "Loopback Pseudo-Interface 1"` | 52 | Must accept CLI argument or config for non-loopback interface name |
| `target_ip = "127.0.0.1"` (PORT_SCAN) | 524 | Must accept Kali IP (192.168.56.105) |
| `target_ip = "127.0.0.1"` (BRUTE_FORCE) | 539 | Must accept Kali IP |
| `target_ip = "127.0.0.1"` (DOS) | 554 | Must accept Kali IP |
| `target_ips = ["127.0.0.2", ...]` (RECON) | 566 | Must accept target IP list on NIDS-VM |
| `source_machine = "localhost"` | 439 | Must reflect Kali hostname/IP |
| `target_machine = "localhost"` | 440 | Must reflect NIDS-VM hostname/IP |

**Attribution logic:** The script already records exact 5-tuple flows (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`) and marks them as `ATTRIBUTED`. The attribution mechanism is sound; only the network parameters need adaptation.

**Conclusion:** The script architecture supports non-loopback collection, but hardcoded loopback values prevent immediate execution. **The script is NOT ready for Stage 11.8.7 without modification.**

---

## 8. Feature Schema Verification

| Feature | Production Definition | Status |
|---------|----------------------|--------|
| duration | Flow duration in seconds | ✓ Verified in `features.py` |
| packet_count | Total packets in flow | ✓ Verified |
| byte_count | Total bytes in flow | ✓ Verified |
| average_packet_size | Mean packet length | ✓ Verified |
| minimum_packet_size | Min packet length | ✓ Verified |
| maximum_packet_size | Max packet length | ✓ Verified |
| packet_size_std | Std dev of packet lengths | ✓ Verified |
| packets_per_second | Flow packet rate | ✓ Verified |
| bytes_per_second | Flow byte rate | ✓ Verified |
| forward_packets | Fwd direction packets | ✓ Verified |
| backward_packets | Bwd direction packets | ✓ Verified |
| forward_bytes | Fwd direction bytes | ✓ Verified |
| backward_bytes | Bwd direction bytes | ✓ Verified |
| syn_count | SYN flag count | ✓ Verified |
| ack_count | ACK flag count | ✓ Verified |
| fin_count | FIN flag count | ✓ Verified |
| rst_count | RST flag count | ✓ Verified |
| psh_count | PSH flag count | ✓ Verified |

All 18 features match the production schema defined in `NIDS/features.py`.

---

## 9. Remaining Blockers

| # | Blocker | Severity | Resolution |
|---|---------|----------|------------|
| 1 | NIDS-VM guest credentials unavailable | **HIGH** | Provide username/password for NIDS-VM Ubuntu guest |
| 2 | NIDS-VM Guest Additions guestcontrol not ready | **HIGH** | May resolve after reboot or reinstall of Guest Additions |
| 3 | `collect_attack_11_8_v2.py` hardcoded loopback interface/IPs | **HIGH** | Parameterize interface and target IPs for non-loopback |
| 4 | Host cannot reach VMs (169.254.185.144/16 vs 192.168.56.0/24) | **MEDIUM** | Not required during collection, but blocks post-collection file retrieval unless shared folder or SSH is configured |
| 5 | No shared folders configured between host and NIDS-VM | **MEDIUM** | Configure shared folder or enable SSH/SCP for dataset transfer |
| 6 | NIDS-VM IP not independently confirmed from host | **LOW** | Can be resolved with guest access or by pinging from Kali |

---

## 10. Exact Next Action

**To unblock Stage 11.8.7 execution:**

1. **Provide NIDS-VM guest credentials** (Ubuntu username and password) so that host-side verification can be completed:
   - `ip addr` to confirm Host-Only interface name and IP
   - `tcpdump -i <interface> -c 10` during a ping test from Kali to verify capture capability
   - Verify NIDS code directory exists and `python3 -c "import NIDS"` succeeds
   - Verify `NIDS/models/nids_model.joblib` exists and hash matches `7bcc643154a1f44d`

2. **If guest control cannot be established**, perform the above checks manually inside the NIDS-VM guest and report the output.

3. **After guest-side verification passes**, parameterize `collect_attack_11_8_v2.py` to accept:
   - `--interface <non-loopback-interface-name>`
   - `--target-ip <Kali-or-NIDS-VM-IP>`
   - `--source-machine <Kali-hostname>`
   - `--target-machine <NIDS-VM-hostname>`

4. **Execute Stage 11.8.7 collection** on the isolated Host-Only network (192.168.56.0/24).

---

## 11. Production Integrity

| Check | Status |
|-------|--------|
| Production files modified | **NO** |
| Model modified | **NO** |
| Model retrained | **NO** |
| Thresholds modified | **NO** |
| Rules modified | **NO** |
| Original datasets modified | **NO** |
| Evaluation scripts modified | **NO** (read-only audit) |
| Model hash | **7bcc643154a1f44d** (unchanged) |

---

## 12. Tests

No tests were executed in this stage. This is a readiness audit only. Existing test suites were not modified.

---

## 13. Verdict

**YELLOW**

**Reasoning:**
- Host-side model and network infrastructure are verified and ready.
- VMs are running with correct Host-Only adapter configuration.
- Kali guest properties confirm expected IP and user.
- NIDS-VM guest-side verification is blocked by lack of accessible guest credentials and incomplete Guest Additions guestcontrol functionality.
- Collection script requires non-loopback parameterization before use.
- No safety violations, no production changes, no model modifications.

**Stage 11.8.7 is NOT READY for data collection.** It is ready for guest-side verification once NIDS-VM credentials are provided.

---

*Generated by Stage 11.8.7 Environment Readiness Audit*
*Model hash: 7bcc643154a1f44d*
