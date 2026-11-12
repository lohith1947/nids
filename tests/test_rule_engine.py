"""
Tests for the Rule Engine.

Tests use synthetic Flow objects (no live packet capture required) to
validate each detection rule against controlled traffic patterns.

Each test simulates the feature profile of one attack class:
  1. BENIGN  — normal bidirectional SSH-like session
  2. PORT_SCAN — sequential SYN-only probes to many ports
  3. BRUTE_FORCE — repeated short connections to the same service port
  4. DOS — extremely high packet rate in a single flow
  5. RECONNAISSANCE — connections to many different hosts

Run from project root:
    python -m NIDS.tests.test_rule_engine
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from NIDS.flow import Flow
from NIDS.rule_engine import (
    RuleEngine,
    RuleResult,
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
)
from NIDS.config import RuleConfig

# TCP flag values
SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
FIN = 0x01
RST = 0x04
PSH = 0x08
PSH_ACK = 0x18
RST_ACK = 0x14


def make_flow(src_ip, dst_ip, src_port, dst_port, protocol=6):
    """Create an empty Flow for testing."""
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )


def make_dos_flow():
    """
    Create a high-volume flow simulating Denial of Service.

    Characteristics:
      - Very high packet rate (>> DOS_PACKETS_PER_SECOND threshold)
      - Very high byte rate (>> DOS_BYTES_PER_SECOND threshold)
      - SYN-heavy (many SYN packets, few ACKs)
    """
    cfg = RuleConfig()
    flow = make_flow("10.0.0.100", "10.0.0.2", 1000, 80)

    # Simulate 10,000 SYN packets over 1 second
    # pps = 10000, bps ~ 10000 * 60 = 600,000
    n_syn = 10000
    n_ack = 10
    t_start = 1000.0
    for i in range(n_syn):
        ts = t_start + i / n_syn  # spread over 1 second
        flow.add_packet(timestamp=ts, packet_size=60, direction="forward", tcp_flags=SYN)
    for i in range(n_ack):
        ts = t_start + i / n_ack
        flow.add_packet(timestamp=ts, packet_size=40, direction="backward", tcp_flags=SYN_ACK)

    return flow


def make_benign_flow():
    """
    Create a normal bidirectional SSH-like session.

    Characteristics:
      - Moderate packet count (~20-30)
      - Bidirectional traffic with data transfer
      - ACK-heavy (established connection)
      - PSH flags present (data transfer)
      - Reasonable rates
    """
    flow = make_flow("10.0.0.10", "10.0.0.2", 50000, 22)

    t = 1000.0
    # TCP handshake
    flow.add_packet(timestamp=t, packet_size=64, direction="forward", tcp_flags=SYN)
    flow.add_packet(timestamp=t + 0.003, packet_size=64, direction="backward", tcp_flags=SYN_ACK)

    # Data transfer (PSH+ACK)
    for i in range(15):
        flow.add_packet(timestamp=t + 0.03 + i * 0.03, packet_size=120, direction="forward", tcp_flags=PSH_ACK)
        flow.add_packet(timestamp=t + 0.06 + i * 0.03, packet_size=200, direction="backward", tcp_flags=PSH_ACK)

    # TCP teardown
    flow.add_packet(timestamp=t + 0.6, packet_size=64, direction="forward", tcp_flags=FIN)
    flow.add_packet(timestamp=t + 0.603, packet_size=64, direction="backward", tcp_flags=ACK)

    return flow


def make_single_port_scan_probe():
    """
    Create a single SYN-only port scan probe flow.

    Characteristics:
      - SYN flag set, ACK not set (connect without completing handshake)
      - Very few packets (1-2)
      - Very short duration
    """
    flow = make_flow("10.0.0.100", "10.0.0.2", 50001, 22)
    flow.add_packet(timestamp=1000.0, packet_size=66, direction="forward", tcp_flags=SYN)
    # No response — scan probe
    return flow


def make_brute_force_flow():
    """
    Create a single short brute-force authentication attempt flow.

    Characteristics:
      - SYN to a common service port (22)
      - Very few packets (2-3: SYN, SYN-ACK, RST)
      - Short duration (< 1s)
      - No PSH flags (no data transferred)
    """
    flow = make_flow("10.0.0.100", "10.0.0.2", 50002, 22)
    flow.add_packet(timestamp=1000.0, packet_size=66, direction="forward", tcp_flags=SYN)
    flow.add_packet(timestamp=1000.001, packet_size=66, direction="backward", tcp_flags=SYN_ACK)
    flow.add_packet(timestamp=1000.002, packet_size=66, direction="forward", tcp_flags=RST)
    return flow


def make_recon_scan_probe():
    """
    Create a single reconnaissance scan probe flow.

    Characteristics:
      - SYN to a common port
      - Very short, no data
    """
    flow = make_flow("10.0.0.100", "10.0.0.50", 50003, 80)
    flow.add_packet(timestamp=1000.0, packet_size=66, direction="forward", tcp_flags=SYN)
    return flow


def test_benign():
    """Test 1: BENIGN traffic should return BENIGN."""
    print("=" * 60)
    print("TEST 1: BENIGN")
    print("=" * 60)
    engine = RuleEngine()
    flow = make_benign_flow()

    print(f"  Flow: {flow}")
    print(f"  Features: {flow.get_feature_dict()}")

    result = engine.process_flow(flow)

    print(f"  Prediction: {result.rule_prediction}")
    print(f"  Confidence: {result.rule_confidence}")
    print(f"  Triggered:  {result.triggered_rules}")
    print(f"  Reason:     {result.rule_reason}")

    ok = result.rule_prediction == BENIGN
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_port_scan():
    """Test 2: PORT_SCAN — multiple SYN-only probes to different ports."""
    print("=" * 60)
    print("TEST 2: PORT_SCAN")
    print("=" * 60)
    engine = RuleEngine()
    cfg = engine.config

    # Simulate scanning ports 20-49 (30 different ports) on the same host
    src_port_base = 40000
    for port in range(20, 50):
        flow = make_flow("10.0.0.100", "10.0.0.2", src_port_base + port, port)
        flow.add_packet(
            timestamp=1000.0 + port * 0.01,
            packet_size=66,
            direction="forward",
            tcp_flags=SYN,
        )
        result = engine.process_flow(flow)
        print(f"  Port {port}: prediction={result.rule_prediction}, "
              f"confidence={result.rule_confidence}, "
              f"rules={result.triggered_rules}")

    # Final result should be PORT_SCAN
    last_result = result
    print(f"\n  Final Prediction: {last_result.rule_prediction}")
    print(f"  Confidence: {last_result.rule_confidence}")
    print(f"  Triggered:  {last_result.triggered_rules}")
    print(f"  Reason:     {last_result.rule_reason}")

    ok = last_result.rule_prediction == PORT_SCAN
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_brute_force():
    """Test 3: BRUTE_FORCE — repeated short connections to SSH port 22."""
    print("=" * 60)
    print("TEST 3: BRUTE_FORCE")
    print("=" * 60)
    engine = RuleEngine()
    cfg = engine.config

    # Simulate 15 failed SSH login attempts
    src_port_base = 50000
    results = []
    for i in range(15):
        flow = make_flow("10.0.0.100", "10.0.0.2", src_port_base + i, 22)
        flow.add_packet(
            timestamp=1000.0 + i * 0.5,
            packet_size=66,
            direction="forward",
            tcp_flags=SYN,
        )
        flow.add_packet(
            timestamp=1000.001 + i * 0.5,
            packet_size=66,
            direction="backward",
            tcp_flags=SYN_ACK,
        )
        flow.add_packet(
            timestamp=1000.002 + i * 0.5,
            packet_size=66,
            direction="forward",
            tcp_flags=RST,
        )
        result = engine.process_flow(flow)
        results.append(result)
        if i < 3 or i >= 13:
            print(f"  Attempt {i+1}: prediction={result.rule_prediction}, "
                  f"confidence={result.rule_confidence}, "
                  f"rules={result.triggered_rules}")

    last_result = results[-1]
    print(f"\n  Final Prediction: {last_result.rule_prediction}")
    print(f"  Confidence: {last_result.rule_confidence}")
    print(f"  Triggered:  {last_result.triggered_rules}")
    print(f"  Reason:     {last_result.rule_reason}")

    ok = last_result.rule_prediction == BRUTE_FORCE
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_dos():
    """Test 4: DOS — extremely high packet/byte rate in a single flow."""
    print("=" * 60)
    print("TEST 4: DOS")
    print("=" * 60)
    engine = RuleEngine()
    flow = make_dos_flow()

    print(f"  Flow: {flow}")
    feats = flow.get_feature_dict()
    print(f"  Key features:")
    print(f"    packets_per_second: {feats['packets_per_second']:.1f}")
    print(f"    bytes_per_second:   {feats['bytes_per_second']:.1f}")
    print(f"    packet_count:       {feats['packet_count']}")
    print(f"    syn_count:          {feats['syn_count']}")
    print(f"    syn_ratio:          {feats['syn_count'] / max(feats['packet_count'], 1):.2f}")

    result = engine.process_flow(flow)

    print(f"\n  Prediction: {result.rule_prediction}")
    print(f"  Confidence: {result.rule_confidence}")
    print(f"  Triggered:  {result.triggered_rules}")
    print(f"  Reason:     {result.rule_reason}")

    ok = result.rule_prediction == DOS
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_reconnaissance():
    """Test 5: RECONNAISSANCE — connections to many different hosts."""
    print("=" * 60)
    print("TEST 5: RECONNAISSANCE")
    print("=" * 60)
    engine = RuleEngine()

    # Simulate scanning 8 different hosts (exceeds RECON_MIN_UNIQUE_IPS=5)
    # Each on a different port
    src_port_base = 60000
    targets = [
        ("10.0.0.50", 22),
        ("10.0.0.51", 80),
        ("10.0.0.52", 443),
        ("10.0.0.53", 22),
        ("10.0.0.54", 23),
        ("10.0.0.55", 139),
        ("10.0.0.56", 445),
        ("10.0.0.57", 3306),
    ]

    results = []
    for i, (dst_ip, dst_port) in enumerate(targets):
        flow = make_flow("10.0.0.100", dst_ip, src_port_base + i, dst_port)
        flow.add_packet(
            timestamp=1000.0 + i * 0.5,
            packet_size=66,
            direction="forward",
            tcp_flags=SYN,
        )
        result = engine.process_flow(flow)
        results.append(result)
        print(f"  Target {dst_ip}:{dst_port} (#{i+1}): prediction={result.rule_prediction}, "
              f"confidence={result.rule_confidence}")

    last_result = results[-1]
    print(f"\n  Final Prediction: {last_result.rule_prediction}")
    print(f"  Confidence: {last_result.rule_confidence}")
    print(f"  Triggered:  {last_result.triggered_rules}")
    print(f"  Reason:     {last_result.rule_reason}")

    ok = last_result.rule_prediction == RECONNAISSANCE
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_dos_high_byte_rate_still_detects():
    """
    Test: A genuinely high-volume sustained flow should still trigger DOS
    via high_byte_rate even with the new packet-count guard.
    """
    print("=" * 60)
    print("TEST 6: high_byte_rate still detects a large/sustained flow")
    print("=" * 60)
    engine = RuleEngine()
    cfg = engine.config

    flow = make_flow("10.0.0.100", "10.0.0.2", 1000, 80)

    # Build a flow with enough packets to clear the guard AND a high byte rate
    n_packets = max(cfg.DOS_MIN_RATE_PACKETS, cfg.DOS_MIN_BYTE_RATE_PACKETS)
    t_start = 1000.0
    for i in range(n_packets):
        ts = t_start + i * 0.002  # ~0.04s total, above the duration guard
        flow.add_packet(timestamp=ts, packet_size=600, direction="forward", tcp_flags=SYN)

    feats = flow.get_feature_dict()
    print(f"  packet_count: {feats['packet_count']}")
    print(f"  bytes_per_second: {feats['bytes_per_second']:.1f}")
    print(f"  bytes_per_second > threshold: {feats['bytes_per_second'] > cfg.DOS_BYTES_PER_SECOND}")

    result = engine.process_flow(flow)
    print(f"  Prediction: {result.rule_prediction}")
    print(f"  Confidence: {result.rule_confidence}")
    print(f"  Triggered:  {result.triggered_rules}")

    # high_byte_rate should fire (and also high_packet_rate)
    assert "high_byte_rate" in result.triggered_rules, f"high_byte_rate should fire, got: {result.triggered_rules}"
    assert result.rule_prediction == DOS, f"Expected DOS, got {result.rule_prediction}"

    print(f"  Result: PASS")
    print()
    return True


def test_dos_near_zero_duration_no_false_positive():
    """
    Test: A tiny near-zero-duration flow must NOT trigger DOS via
    high_byte_rate even though its byte-rate may be astronomically high.
    """
    print("=" * 60)
    print("TEST 7: near-zero-duration flow must NOT trigger DOS")
    print("=" * 60)
    engine = RuleEngine()

    # Use port 8080 (not in BRUTE_FORCE_PORTS) so only DOS is evaluated
    flow = make_flow("10.0.0.100", "10.0.0.2", 1000, 8080)

    # Simulate the exact false-positive pattern: 2 packets, ~85 us duration
    # bytes_per_second will be ~1,000,000+, well above threshold
    t = 1000.0
    flow.add_packet(timestamp=t, packet_size=60, direction="forward", tcp_flags=SYN)
    flow.add_packet(timestamp=t + 0.000025, packet_size=41, direction="backward", tcp_flags=SYN_ACK)

    feats = flow.get_feature_dict()
    print(f"  packet_count: {feats['packet_count']}")
    print(f"  byte_count: {feats['byte_count']}")
    print(f"  duration: {feats['duration']:.6f}")
    print(f"  bytes_per_second: {feats['bytes_per_second']:.1f}")
    print(f"  bytes_per_second > threshold: {feats['bytes_per_second'] > engine.config.DOS_BYTES_PER_SECOND}")
    print(f"  packet_count >= DOS_MIN_BYTE_RATE_PACKETS: {feats['packet_count'] >= engine.config.DOS_MIN_BYTE_RATE_PACKETS}")

    result = engine.process_flow(flow)
    print(f"  Prediction: {result.rule_prediction}")
    print(f"  Confidence: {result.rule_confidence}")
    print(f"  Triggered:  {result.triggered_rules}")

    # Must NOT trigger high_byte_rate (or any DOS rule)
    assert "high_byte_rate" not in result.triggered_rules, \
        f"high_byte_rate should NOT fire for tiny flow, but it did: {result.triggered_rules}"
    assert "high_packet_rate" not in result.triggered_rules, \
        f"high_packet_rate should NOT fire for tiny flow, but it did: {result.triggered_rules}"
    assert "syn_flood_pattern" not in result.triggered_rules, \
        f"syn_flood_pattern should NOT fire for tiny flow, but it did: {result.triggered_rules}"
    assert result.rule_prediction == BENIGN, f"Expected BENIGN, got {result.rule_prediction}"

    print(f"  Result: PASS")
    print()
    return True


def test_connect_scan_open_port_not_dos():
    """
    Test: A completed connect-scan handshake to an OPEN port must NOT be
    scored as DoS.

    Regression for the live Kali -> Ubuntu scan.  The port-22 flow carried
    SYN, SYN-ACK, ACK and RST over ~1.2 ms.  Dividing 4 packets by that
    duration reports thousands of packets/s and >180 kB/s, which used to fire
    high_packet_rate + high_byte_rate and produce a CRITICAL DOS alert.
    """
    print("=" * 60)
    print("TEST: connect-scan handshake on an open port is not DOS")
    print("=" * 60)
    engine = RuleEngine()

    flow = make_flow("192.168.56.105", "192.168.56.107", 37130, 22)
    t = 1000.0
    flow.add_packet(timestamp=t, packet_size=60, direction="forward", tcp_flags=SYN)
    flow.add_packet(timestamp=t + 0.0004, packet_size=60, direction="backward", tcp_flags=SYN_ACK)
    flow.add_packet(timestamp=t + 0.0008, packet_size=52, direction="forward", tcp_flags=ACK)
    flow.add_packet(timestamp=t + 0.0012, packet_size=52, direction="forward", tcp_flags=RST)

    feats = flow.get_feature_dict()
    print(f"  packet_count: {feats['packet_count']}")
    print(f"  duration: {feats['duration']:.6f}")
    print(f"  packets_per_second: {feats['packets_per_second']:.0f}")
    print(f"  bytes_per_second: {feats['bytes_per_second']:.0f}")

    result = engine.process_flow(flow)
    print(f"  Prediction: {result.rule_prediction}")
    print(f"  Triggered:  {result.triggered_rules}")

    assert "high_packet_rate" not in result.triggered_rules, \
        f"high_packet_rate must not fire for a handshake, got: {result.triggered_rules}"
    assert "high_byte_rate" not in result.triggered_rules, \
        f"high_byte_rate must not fire for a handshake, got: {result.triggered_rules}"
    assert result.rule_prediction != DOS, \
        f"connect-scan handshake must not be DOS, got {result.rule_prediction}"

    print("  Result: PASS")
    print()
    return True


def test_refused_probe_not_brute_force():
    """
    Test: A scan probe refused with RST must NOT be labeled BRUTE_FORCE.

    Regression for the live Kali -> Ubuntu run.  The 2-packet SYN / RST+ACK
    flow to port 445 (145 us, syn=1 ack=1 rst=1 psh=0) was scored HIGH
    BRUTE_FORCE via short_auth_attempt even though the port was simply closed.
    """
    print("=" * 60)
    print("TEST: refused probe on a closed port is not BRUTE_FORCE")
    print("=" * 60)
    engine = RuleEngine()

    flow = make_flow("192.168.56.105", "192.168.56.107", 47250, 445)
    flow.add_packet(timestamp=1000.0, packet_size=74, direction="forward", tcp_flags=SYN)
    flow.add_packet(timestamp=1000.000145, packet_size=54, direction="backward", tcp_flags=RST_ACK)

    result = engine.process_flow(flow)
    print(f"  Prediction: {result.rule_prediction}")
    print(f"  Triggered:  {result.triggered_rules}")

    assert "short_auth_attempt" not in result.triggered_rules, \
        f"a RST-refused probe must not count as an auth attempt, got: {result.triggered_rules}"
    assert result.rule_prediction != BRUTE_FORCE, \
        f"refused probe must not be BRUTE_FORCE, got {result.rule_prediction}"

    # Repeated refused probes to one closed service must not accumulate into
    # a brute-force campaign.
    engine_refused = RuleEngine()
    for i in range(6):
        refused = make_flow("192.168.56.105", "192.168.56.107", 48000 + i, 445)
        ts = 1000.0 + i * 0.5
        refused.add_packet(timestamp=ts, packet_size=74, direction="forward", tcp_flags=SYN)
        refused.add_packet(timestamp=ts + 0.000145, packet_size=54, direction="backward", tcp_flags=RST_ACK)
        refused_result = engine_refused.process_flow(refused)
    assert refused_result.rule_prediction != BRUTE_FORCE, \
        f"repeated refused probes must not be BRUTE_FORCE, got {refused_result.rule_prediction}"

    # Repeated connections to the same service must still be detected.
    engine2 = RuleEngine()
    for i in range(6):
        f = make_flow("10.0.0.100", "10.0.0.2", 50000 + i, 22)
        f.add_packet(timestamp=1000.0 + i * 0.5, packet_size=66, direction="forward", tcp_flags=SYN)
        f.add_packet(timestamp=1000.001 + i * 0.5, packet_size=66, direction="backward", tcp_flags=SYN_ACK)
        f.add_packet(timestamp=1000.002 + i * 0.5, packet_size=66, direction="forward", tcp_flags=RST)
        result2 = engine2.process_flow(f)
    print(f"  Repeated attempts: {result2.rule_prediction} {result2.triggered_rules}")
    assert result2.rule_prediction == BRUTE_FORCE, \
        f"repeated connections must still be BRUTE_FORCE, got {result2.rule_prediction}"

    print("  Result: PASS")
    print()
    return True


def test_low_rate_scan_not_cross_flow_dos():
    """A 25 SYN/s port scan must remain a scan, not cross-flow DoS."""
    engine = RuleEngine()
    last_result = None
    for i in range(40):
        flow = make_flow("192.168.56.105", "192.168.56.107", 40000 + i, 1000 + i)
        flow.add_packet(
            timestamp=1000.0 + i / 25.0,
            packet_size=60,
            direction="forward",
            tcp_flags=SYN,
        )
        last_result = engine.process_flow(flow)
        assert "syn_flood_cross_flow" not in last_result.triggered_rules, \
            f"25 SYN/s scan triggered cross-flow DoS at probe {i}: {last_result}"
    assert last_result.rule_prediction == PORT_SCAN
    return True


def test_sustained_cross_flow_syn_flood_detected():
    """A sustained 200 SYN/s campaign still triggers cross-flow DoS."""
    engine = RuleEngine()
    last_result = None
    for i in range(200):
        flow = make_flow("10.0.0.100", "10.0.0.2", 30000 + i, 10000)
        flow.add_packet(
            timestamp=1000.0 + i / 200.0,
            packet_size=60,
            direction="forward",
            tcp_flags=SYN,
        )
        last_result = engine.process_flow(flow)
    assert last_result.rule_prediction == DOS
    assert "syn_flood_cross_flow" in last_result.triggered_rules
    return True


def test_dos_byte_rate_boundary():
    """
    Test: Boundary case for DOS_MIN_RATE_PACKETS.
    A flow with exactly DOS_MIN_RATE_PACKETS packets and high byte rate
    SHOULD trigger; a flow with one packet fewer should NOT, even though its
    arithmetic byte rate is far above threshold.
    """
    print("=" * 60)
    print("TEST 8: DOS_MIN_RATE_PACKETS boundary")
    print("=" * 60)
    cfg = RuleConfig()

    # Case A: exactly at the configured threshold.
    # Use port 8080 to avoid BRUTE_FORCE interference on port 80
    flow_at = make_flow("10.0.0.100", "10.0.0.2", 1000, 8080)
    t_start = 1000.0
    for i in range(cfg.DOS_MIN_RATE_PACKETS):
        ts = t_start + i * 0.002
        flow_at.add_packet(timestamp=ts, packet_size=600, direction="forward", tcp_flags=SYN)

    engine_a = RuleEngine()
    result_a = engine_a.process_flow(flow_at)
    print(f"  At threshold ({cfg.DOS_MIN_RATE_PACKETS} pkts): pred={result_a.rule_prediction}, rules={result_a.triggered_rules}")
    assert "high_byte_rate" in result_a.triggered_rules, \
        f"high_byte_rate should fire at threshold, got: {result_a.triggered_rules}"

    # Case B: one packet below the configured threshold.
    # Use port 8080 to avoid BRUTE_FORCE interference
    flow_below = make_flow("10.0.0.101", "10.0.0.2", 2000, 8080)
    for i in range(cfg.DOS_MIN_RATE_PACKETS - 1):
        ts = t_start + i * 0.0001  # very short duration to keep high byte rate
        flow_below.add_packet(timestamp=ts, packet_size=600, direction="forward", tcp_flags=SYN)

    # Verify byte rate is still high
    feats_b = flow_below.get_feature_dict()
    print(f"  Below threshold ({feats_b['packet_count']} pkts): bytes_per_second={feats_b['bytes_per_second']:.1f}")
    print(f"  bytes_per_second > threshold: {feats_b['bytes_per_second'] > cfg.DOS_BYTES_PER_SECOND}")

    engine_b = RuleEngine()
    result_b = engine_b.process_flow(flow_below)
    print(f"  Below threshold: pred={result_b.rule_prediction}, rules={result_b.triggered_rules}")
    assert "high_byte_rate" not in result_b.triggered_rules, \
        f"high_byte_rate should NOT fire below threshold, got: {result_b.triggered_rules}"

    print(f"  Result: PASS")
    print()
    return True


def test_port_scan_loopback_not_flagged():
    """
    Test: Normal loopback traffic contacting many ports must NOT be
    classified as PORT_SCAN solely because all connections use 127.0.0.1.
    """
    print("=" * 60)
    print("TEST 9: Loopback port scan false-positive suppression")
    print("=" * 60)
    engine = RuleEngine()
    cfg = engine.config

    # Simulate 15 benign loopback connections to different ports
    # on 127.0.0.1 (e.g. local OS services: DNS, HTTP, X11, etc.)
    src_port_base = 50000
    for port in range(20, 35):  # 15 different ports
        flow = make_flow("127.0.0.1", "127.0.0.1", src_port_base + port, port)
        # Benign loopback: small SYN-only connection (no response, typical for
        # local service probes)
        flow.add_packet(
            timestamp=1000.0 + port * 0.5,
            packet_size=66,
            direction="forward",
            tcp_flags=SYN,
        )
        result = engine.process_flow(flow)

    # With 15 unique ports from 127.0.0.1, the cross_flow_port_scan rule
    # would normally fire (15 >= 10). The loopback guard should prevent it.
    print(f"  Unique ports contacted: 15")
    print(f"  Threshold: {cfg.PORT_SCAN_MIN_UNIQUE_PORTS}")
    print(f"  Last prediction: {result.rule_prediction}")
    print(f"  Last triggered:  {result.triggered_rules}")

    # The per-flow SYN-only probe check is fine to fire (low confidence),
    # but cross_flow_port_scan must NOT fire for loopback.
    assert "cross_flow_port_scan" not in result.triggered_rules, \
        f"cross_flow_port_scan should NOT fire for loopback, got: {result.triggered_rules}"

    print(f"  Result: PASS")
    print()
    return True


def test_port_scan_non_loopback_still_detects():
    """
    Test: Existing cross-flow port-scan behavior for non-loopback traffic
    must remain intact.
    """
    print("=" * 60)
    print("TEST 10: Non-loopback port scan still detected")
    print("=" * 60)
    engine = RuleEngine()
    cfg = engine.config

    # Use the same pattern as the original test_port_scan
    src_port_base = 40000
    for port in range(20, 50):
        flow = make_flow("10.0.0.100", "10.0.0.2", src_port_base + port, port)
        flow.add_packet(
            timestamp=1000.0 + port * 0.01,
            packet_size=66,
            direction="forward",
            tcp_flags=SYN,
        )
        result = engine.process_flow(flow)

    print(f"  Ports scanned: 30")
    print(f"  Threshold: {cfg.PORT_SCAN_MIN_UNIQUE_PORTS}")
    print(f"  Final prediction: {result.rule_prediction}")
    print(f"  Triggered:  {result.triggered_rules}")

    assert result.rule_prediction == PORT_SCAN, \
        f"Expected PORT_SCAN for non-loopback, got {result.rule_prediction}"
    assert "cross_flow_port_scan" in result.triggered_rules, \
        f"cross_flow_port_scan should fire for non-loopback, got: {result.triggered_rules}"

    print(f"  Result: PASS")
    print()
    return True


def test_other_rules_unaffected_by_loopback():
    """
    Test: Loopback guard only affects cross_flow_port_scan and multi_port_scan;
    other rules (DOS, BRUTE_FORCE, multi_host_scan RECONNAISSANCE) should
    still evaluate normally for loopback traffic.
    """
    print("=" * 60)
    print("TEST 11: Non-port-scan rules unaffected by loopback")
    print("=" * 60)

    # DOS with loopback source should still detect (uses per-flow checks)
    engine = RuleEngine()
    cfg = engine.config
    flow = make_flow("127.0.0.1", "127.0.0.1", 1000, 8080)
    t_start = 1000.0
    for i in range(cfg.DOS_MIN_RATE_PACKETS):
        ts = t_start + i * 0.002
        flow.add_packet(timestamp=ts, packet_size=600, direction="forward", tcp_flags=SYN)

    result = engine.process_flow(flow)
    print(f"  DOS loopback: pred={result.rule_prediction}, rules={result.triggered_rules}")
    assert result.rule_prediction == DOS, f"DOS should still work for loopback, got {result.rule_prediction}"

    # RECON multi_host_scan with loopback source: contacts many different dst IPs
    engine2 = RuleEngine()
    for i in range(cfg.RECON_MIN_UNIQUE_IPS):
        dst_ip = f"10.0.0.{50 + i}"
        flow_r = make_flow("127.0.0.1", dst_ip, 60000 + i, 80)
        flow_r.add_packet(timestamp=1000.0 + i * 0.5, packet_size=66, direction="forward", tcp_flags=SYN)
        result_r = engine2.process_flow(flow_r)

    print(f"  RECON loopback (multi_host): pred={result_r.rule_prediction}, rules={result_r.triggered_rules}")
    assert "multi_port_scan" not in result_r.triggered_rules, \
        f"multi_port_scan should NOT fire for loopback, got: {result_r.triggered_rules}"
    assert "multi_host_scan" in result_r.triggered_rules, \
        f"multi_host_scan should fire for loopback (different dst IPs), got: {result_r.triggered_rules}"

    print(f"  Result: PASS")
    print()
    return True


def main():
    """Run all tests and report results."""
    print("\n" + "=" * 60)
    print("NIDS RULE ENGINE TESTS")
    print("=" * 60 + "\n")

    results = []
    results.append(("BENIGN", test_benign()))
    results.append(("PORT_SCAN", test_port_scan()))
    results.append(("BRUTE_FORCE", test_brute_force()))
    results.append(("DOS", test_dos()))
    results.append(("RECONNAISSANCE", test_reconnaissance()))
    results.append(("high_byte_rate still detects", test_dos_high_byte_rate_still_detects()))
    results.append(("near-zero-duration no FP", test_dos_near_zero_duration_no_false_positive()))
    results.append(("connect-scan open port not DOS", test_connect_scan_open_port_not_dos()))
    results.append(("refused probe not brute force", test_refused_probe_not_brute_force()))
    results.append(("low-rate scan not cross-flow DOS", test_low_rate_scan_not_cross_flow_dos()))
    results.append(("sustained cross-flow SYN flood", test_sustained_cross_flow_syn_flood_detected()))
    results.append(("DOS_MIN_RATE_PACKETS boundary", test_dos_byte_rate_boundary()))
    results.append(("loopback port scan suppressed", test_port_scan_loopback_not_flagged()))
    results.append(("non-loopback port scan intact", test_port_scan_non_loopback_still_detects()))
    results.append(("other rules unaffected by loopback", test_other_rules_unaffected_by_loopback()))

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {name:20s} {status}")

    all_passed = all(p for _, p in results)
    print(f"\n  Overall: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    print()
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
