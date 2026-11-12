"""
Regression test for the full NIDS pipeline.

Verifies that the recreated foundation (packet capture, flow management,
feature extraction) still works end-to-end with the new Rule Engine.

Uses synthetic packet info dicts (as produced by parse_packet_info) to
simulate Scapy capture on a Windows development machine where no live
host-only network is available.

Run from project root:
    python -m NIDS.tests.test_regression
"""

import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from NIDS.flow import Flow
from NIDS.flow_manager import FlowManager
from NIDS.features import NUMERIC_FEATURE_NAMES
from NIDS.rule_engine import RuleEngine, BENIGN, DOS
from NIDS.packet_capture import parse_packet_info
from NIDS.config import FlowConfig
from pathlib import Path

# Optional: ML model (only if trained model exists)
try:
    from NIDS.model import NIDSModel
    _MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "nids_model.joblib"
    _MODEL_AVAILABLE = _MODEL_PATH.exists()
except Exception:
    _MODEL_AVAILABLE = False

# TCP flag values
SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
FIN = 0x01
RST = 0x04
PSH = 0x08
PSH_ACK = 0x18


def make_pkt_info(src_ip, dst_ip, src_port, dst_port, proto=6,
                  flags=0, pkt_len=64):
    """Create a packet info dict compatible with FlowManager.process_packet_info."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "packet_len": pkt_len,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flags,
        "has_tcp": proto == 6,
        "has_udp": proto == 17,
        "has_icmp": proto == 1,
    }


def test_benign_ssh_session():
    """
    Regression: simulate a normal SSH session through the FlowManager.
    Verify bidirectional flow merging and feature extraction.
    """
    print("=" * 60)
    print("REGRESSION TEST 1: Benign SSH session via FlowManager")
    print("=" * 60)

    fm = FlowManager(flow_timeout=5.0)
    engine = RuleEngine()

    # Simulate TCP handshake + data + teardown with small delay between flows
    # Use timestamps spread over 2 seconds, packets close together
    t = 1000.0

    # SYN (Kali -> Ubuntu)
    p1 = make_pkt_info("192.168.56.105", "192.168.56.107", 56202, 22,
                       flags=SYN, pkt_len=66)
    p1["time"] = t
    # We need to set time on the packet for process_packet_info to use it
    # But process_packet_info takes info dict and timestamp separately

    # Use process_packet_info directly with explicit timestamps
    completed = []
    completed.extend(fm.process_packet_info(p1, t))

    # SYN-ACK (Ubuntu -> Kali)
    p2 = make_pkt_info("192.168.56.107", "192.168.56.105", 22, 56202,
                       flags=SYN_ACK, pkt_len=66)
    completed.extend(fm.process_packet_info(p2, t + 0.001))

    # Data transfer (3 data packets each direction)
    for i in range(3):
        p_fwd = make_pkt_info("192.168.56.105", "192.168.56.107", 56202, 22,
                              flags=PSH_ACK, pkt_len=120)
        completed.extend(fm.process_packet_info(p_fwd, t + 0.01 + i * 0.01))

        p_bwd = make_pkt_info("192.168.56.107", "192.168.56.105", 22, 56202,
                              flags=PSH_ACK, pkt_len=200)
        completed.extend(fm.process_packet_info(p_bwd, t + 0.02 + i * 0.01))

    # FIN + ACK teardown
    p_fin = make_pkt_info("192.168.56.105", "192.168.56.107", 56202, 22,
                          flags=FIN, pkt_len=66)
    completed.extend(fm.process_packet_info(p_fin, t + 0.2))

    p_ack = make_pkt_info("192.168.56.107", "192.168.56.105", 22, 56202,
                          flags=ACK, pkt_len=64)
    completed.extend(fm.process_packet_info(p_ack, t + 0.201))

    # Force-close: send a packet to a DIFFERENT 5-tuple at a later timestamp.
    # This triggers the timeout check; the SSH flow (last packet at t+0.201)
    # should be closed because it exceeds the flow_timeout (5s).
    time_trigger = t + 10.0
    trigger_pkt = make_pkt_info(
        "192.168.56.99", "192.168.56.107", 40000, 443,
        flags=SYN, pkt_len=66
    )
    completed = fm.process_packet_info(trigger_pkt, time_trigger)

    print(f"  Active flows remaining: {fm.get_active_flow_count()}")
    print(f"  Completed flows: {len(completed)}")

    ok1 = len(completed) >= 1  # SSH flow was closed by timeout
    ok2 = len(completed) >= 1
    print(f"  Flows completed on timeout: {ok1}")
    print(f"  Flows returned: {ok2}")

    if completed:
        flow = completed[0]
        feats = flow.get_feature_dict()
        print(f"\n  Flow identity:")
        print(f"    src_ip: {flow.src_ip}")
        print(f"    dst_ip: {flow.dst_ip}")
        print(f"    src_port: {flow.src_port}")
        print(f"    dst_port: {flow.dst_port}")
        print(f"    protocol: {flow.protocol}")

        print(f"\n  Flow statistics:")
        print(f"    duration: {feats['duration']:.4f}")
        print(f"    packet_count: {feats['packet_count']}")
        print(f"    byte_count: {feats['byte_count']}")
        print(f"    average_packet_size: {feats['average_packet_size']:.2f}")
        print(f"    minimum_packet_size: {feats['minimum_packet_size']}")
        print(f"    maximum_packet_size: {feats['maximum_packet_size']}")
        print(f"    packet_size_std: {feats['packet_size_std']:.2f}")
        print(f"    packets_per_second: {feats['packets_per_second']:.2f}")
        print(f"    bytes_per_second: {feats['bytes_per_second']:.2f}")

        print(f"\n  Directional stats:")
        print(f"    forward_packets: {feats['forward_packets']}")
        print(f"    backward_packets: {feats['backward_packets']}")
        print(f"    forward_bytes: {feats['forward_bytes']}")

        print(f"\n  TCP flags:")
        print(f"    syn_count: {feats['syn_count']}")
        print(f"    ack_count: {feats['ack_count']}")
        print(f"    fin_count: {feats['fin_count']}")
        print(f"    rst_count: {feats['rst_count']}")
        print(f"    psh_count: {feats['psh_count']}")

        # Verify bidirectional: should have both forward and backward packets
        ok_bidir = feats['forward_packets'] > 0 and feats['backward_packets'] > 0
        print(f"\n  Bidirectional flow: {ok_bidir}")
        print(f"    forward/backward packets: {feats['forward_packets']}/{feats['backward_packets']}")

        # Verify feature count matches definition
        feature_count = len(flow.get_features())
        name_count = len(NUMERIC_FEATURE_NAMES)
        ok_features = feature_count == name_count
        print(f"\n  Feature count: {feature_count} (expected {name_count}): {ok_features}")

        # Verify feature dict keys match
        ok_keys = set(feats.keys()) == set(NUMERIC_FEATURE_NAMES)
        print(f"  Feature dict keys match definitions: {ok_keys}")

        # Run through Rule Engine
        result = engine.process_flow(flow)
        print(f"\n  Rule Engine prediction: {result.rule_prediction}")
        print(f"  Confidence: {result.rule_confidence}")
        print(f"  Triggered: {result.triggered_rules}")

        ok3 = result.rule_prediction == BENIGN
        print(f"\n  SSH session classified as BENIGN: {ok3}")

    all_ok = ok1 and ok2
    if completed:
        all_ok = all_ok and ok_bidir and ok_features and ok_keys and ok3
    print(f"\n  Result: {'PASS' if all_ok else 'FAIL'}")
    print()
    return all_ok


def test_dos_pipeline():
    """
    Regression: verify a DoS flow is detected through the full pipeline.
    """
    print("=" * 60)
    print("REGRESSION TEST 2: DoS detection via FlowManager + RuleEngine")
    print("=" * 60)

    fm = FlowManager(flow_timeout=5.0)
    engine = RuleEngine()

    t = 1000.0
    src_ip = "192.168.56.105"
    dst_ip = "192.168.56.107"
    src_port = 33333
    dst_port = 80

    # Simulate 1000 SYN packets (SYN flood) over 0.5 seconds
    completed = []
    for i in range(1000):
        pkt = make_pkt_info(src_ip, dst_ip, src_port, dst_port,
                            flags=SYN, pkt_len=60)
        completed = fm.process_packet_info(pkt, t + i * 0.0005)

    # Force timeout to close the DoS flow by sending a packet to a DIFFERENT
    # 5-tuple (a different connection) at a later timestamp.
    trigger_pkt = make_pkt_info(
        "10.0.0.99", "10.0.0.50", 40000, 443,
        flags=SYN, pkt_len=66
    )
    completed = fm.process_packet_info(trigger_pkt, t + 10.0)

    if completed:
        flow = completed[0]
        feats = flow.get_feature_dict()
        print(f"  Flow: {flow}")
        print(f"  packets_per_second: {feats['packets_per_second']:.1f}")
        print(f"  bytes_per_second: {feats['bytes_per_second']:.1f}")
        print(f"  packet_count: {feats['packet_count']}")
        print(f"  syn_count: {feats['syn_count']}")
        print(f"  syn_ratio: {feats['syn_count'] / max(feats['packet_count'], 1):.2f}")

        result = engine.process_flow(flow)
        print(f"\n  Rule Engine prediction: {result.rule_prediction}")
        print(f"  Confidence: {result.rule_confidence}")
        print(f"  Triggered: {result.triggered_rules}")
        print(f"  Reason: {result.rule_reason}")

        ok = result.rule_prediction == DOS
        print(f"\n  Result: {'PASS' if ok else 'FAIL'}")
        print()
        return ok

    print("  No completed flows — FAIL")
    print()
    return False


def run_scenario(name, packets_fn, expected_class, engine=None):
    """Generic scenario test (placeholder for future expansion)."""
    print("=" * 60)
    print(f"TEST: {name}")
    print("=" * 60)
    if engine is None:
        engine = RuleEngine()
    fm = FlowManager(flow_timeout=2.0)
    completed = []

    # Run all packets
    for pkt_info, ts in packets_fn():
        completed.extend(fm.process_packet_info(pkt_info, ts))

    # Force timeout
    for flow in fm.get_all_flows():
        completed.append(flow)
    fm.reset()

    # Check results
    ok = False
    for flow in completed:
        result = engine.process_flow(flow)
        if result.rule_prediction == expected_class:
            ok = True
            print(f"  Flow {flow}: -> {result.rule_prediction} (conf={result.rule_confidence})")

    print(f"  Expected: {expected_class}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_model_integration():
    """
    Verify that a Flow object's 18-feature vector is compatible with the
    trained Random Forest model (feature order, count, and prediction).
    """
    print("=" * 60)
    print("REGRESSION TEST 3: ML Model - Feature Compatibility")
    print("=" * 60 + "\n")

    if not _MODEL_AVAILABLE:
        print("  [SKIP] Trained model not found at NIDS/models/nids_model.joblib")
        print("         Run 'python -m NIDS.train_model' first.")
        print()
        return True

    print("  Loading trained model...")
    model = NIDSModel.load(_MODEL_PATH)
    print(f"  Classes: {model.classes_}")
    print()

    # Build a benign-like flow
    flow = Flow("10.0.0.10", "10.0.0.2", 50000, 22, 6)
    for i in range(17):
        flow.add_packet(0.0 + i * 0.01, 100 + i * 10, "forward", 0x10 if i > 0 else 0x02)
    for i in range(17):
        flow.add_packet(0.0 + i * 0.01, 150 + i * 5, "backward", 0x18)

    features = flow.get_features()

    # Verify feature count and names
    ok_count = len(features) == 18
    ok_names = list(flow.get_feature_dict().keys()) == NUMERIC_FEATURE_NAMES
    print(f"  Feature count: {len(features)} (expected 18): {ok_count}")
    print(f"  Feature names match definitions: {ok_names}")
    print()

    # Run model prediction
    label, conf = model.predict(features)
    print(f"  Flow features: {[round(x, 2) if isinstance(x, float) else x for x in features]}")
    print(f"  Model prediction: {label}")
    print(f"  Confidence: {conf:.3f}")
    print()

    ok = ok_count and ok_names
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def main():
    print("\n" + "=" * 60)
    print("NIDS PIPELINE REGRESSION TESTS")
    print("=" * 60 + "\n")

    results = []
    results.append(("Benign SSH via FlowManager", test_benign_ssh_session()))
    results.append(("DoS via FlowManager", test_dos_pipeline()))
    results.append(("ML Model - Feature Compatibility", test_model_integration()))

    print("=" * 60)
    print("REGRESSION SUMMARY")
    print("=" * 60)
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {name:40s} {status}")

    all_passed = all(p for _, p in results)
    print(f"\n  Overall: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    print()
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
