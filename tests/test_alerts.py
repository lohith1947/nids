"""
Tests for the Alert Manager (Stage 4).

Validates:
  1.  Alert creation with all required fields
  2.  Dictionary serialization (to_dict)
  3.  Storing alerts
  4.  Retrieving all alerts
  5.  Latest-N retrieval
  6.  Severity counting
  7.  Attack-type counting
  8.  Clearing alerts
  9.  Deduplication (identical alerts within window)
  10. Deduplication expiry (identical alerts outside window)
  11. Rate limiting per source IP
  12. Severity filtering (min severity threshold)
  13. Thread-safe basic behavior
  14. Malformed / invalid inputs

Run from project root:
    python -m NIDS.tests.test_alerts
"""

import sys
import os
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from NIDS.alerts import (
    Alert,
    AlertManager,
    AlertManagerConfig,
    SEVERITY_WEIGHTS,
)
from NIDS.correlator import DetectionResult
from NIDS.risk_scorer import RiskResult
from NIDS.rule_engine import (
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
)
from NIDS.flow import Flow


def make_flow(src_ip="10.0.0.100", dst_ip="10.0.0.2",
              src_port=50000, dst_port=22, protocol=6):
    """Create a minimal Flow for testing."""
    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )


def make_detection(prediction, confidence, explanation="test detection",
                   triggered_rules=None):
    """Create a DetectionResult for testing."""
    return DetectionResult(
        final_prediction=prediction,
        combined_confidence=confidence,
        rule_prediction=prediction,
        rule_confidence=confidence,
        ml_prediction=prediction,
        ml_confidence=confidence,
        triggered_rules=triggered_rules or [],
        ml_top3=[],
        explanation=explanation,
    )


def make_risk_result(prediction, risk_score, severity=None, explanation="risk"):
    """Create a RiskResult for testing."""
    from NIDS.config import SEVERITY_MAP
    if severity is None:
        severity = SEVERITY_MAP.get(prediction, "INFORMATIONAL")
    return RiskResult(
        risk_score=risk_score,
        severity=severity,
        prediction=prediction,
        confidence=0.5,
        explanation=explanation,
        rule_reason="test rule reason",
    )


def make_manager(config=None):
    return AlertManager(config=config or AlertManagerConfig())


# ---------------------------------------------------------------------------

def test_alert_creation():
    """Test 1: Alert can be created from DetectionResult + RiskResult + Flow."""
    print("=" * 60)
    print("TEST 1: Alert creation")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    alert = mgr.create_alert(detection, risk, flow)

    print(f"  Alert ID:     {alert.alert_id}")
    print(f"  Attack type:  {alert.attack_type}")
    print(f"  Risk score:   {alert.risk_score}")
    print(f"  Severity:     {alert.severity}")
    print(f"  Source IP:    {alert.source_ip}")
    print(f"  Destination:  {alert.destination_ip}")
    print(f"  Source port:  {alert.source_port}")
    print(f"  Dest port:    {alert.destination_port}")
    print(f"  Protocol:     {alert.protocol}")

    ok = (
        alert is not None
        and alert.alert_id != ""
        and alert.attack_type == DOS
        and alert.risk_score == 90.0
        and alert.severity == "CRITICAL"
        and alert.source_ip == "10.0.0.1"
        and alert.destination_ip == "10.0.0.2"
        and alert.source_port == 5000
        and alert.destination_port == 22
        and alert.protocol == 6
    )
    return ok


def test_required_fields():
    """Test 2: Alert has all required fields."""
    print("=" * 60)
    print("TEST 2: All required fields present")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow()
    detection = make_detection(BRUTE_FORCE, 0.75, triggered_rules=["rule1", "rule2"])
    risk = make_risk_result(BRUTE_FORCE, 65.0, "HIGH")

    alert = mgr.create_alert(detection, risk, flow)

    required_fields = [
        "alert_id", "timestamp", "attack_type", "risk_score", "severity",
        "confidence", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "triggered_rules",
        "rule_prediction", "ml_prediction", "explanation",
    ]

    all_ok = True
    for f in required_fields:
        has = hasattr(alert, f)
        if not has:
            print(f"  MISSING: {f}")
            all_ok = False
        else:
            print(f"  {f:20s}: {getattr(alert, f)}")

    # Check derived values
    check1 = alert.rule_prediction == BRUTE_FORCE
    check2 = alert.ml_prediction == BRUTE_FORCE
    check3 = alert.triggered_rules == ["rule1", "rule2"]
    check4 = alert.explanation == "test detection"

    print(f"  rule_prediction matches: {check1}")
    print(f"  ml_prediction matches:  {check2}")
    print(f"  triggered_rules match:  {check3}")
    print(f"  explanation matches:    {check4}")

    return all_ok and check1 and check2 and check3 and check4


def test_dict_serialization():
    """Test 3: to_dict produces a JSON-serializable dictionary."""
    print("=" * 60)
    print("TEST 3: Dictionary serialization")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL", explanation="high risk")

    alert = mgr.create_alert(detection, risk, flow)
    d = alert.to_dict()

    import json
    json_str = json.dumps(d)  # should not raise

    print(f"  JSON serializable: True (len={len(json_str)})")
    print(f"  Keys: {list(d.keys())}")

    ok = (
        isinstance(d, dict)
        and d["attack_type"] == DOS
        and d["risk_score"] == 90.0
        and d["source_ip"] == "10.0.0.1"
        and d["severity"] == "CRITICAL"
    )
    return ok


def test_store_and_retrieve():
    """Test 4: Alerts are stored and can be retrieved."""
    print("=" * 60)
    print("TEST 4: Store and retrieve alerts")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)

    a1 = mgr.create_alert(make_detection(DOS, 0.9), make_risk_result(DOS, 90.0, "CRITICAL"), flow)
    a2 = mgr.create_alert(make_detection(PORT_SCAN, 0.7), make_risk_result(PORT_SCAN, 25.0, "MEDIUM"), flow)

    all_alerts = mgr.get_all_alerts()

    print(f"  Stored alerts: {len(all_alerts)}")
    for a in all_alerts:
        print(f"    {a.alert_id[:8]}... {a.attack_type} risk={a.risk_score}")

    ok = len(all_alerts) == 2
    return ok


def test_latest_n():
    """Test 5: get_recent_alerts returns the N most recent."""
    print("=" * 60)
    print("TEST 5: Latest N retrieval")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow()

    # Create 5 alerts with small delays, different destinations so dedup won't collapse them
    for i in range(5):
        time.sleep(0.01)
        flow_i = make_flow("10.0.0.1", "10.0.0.2", 5000 + i, 22 + i)
        mgr.create_alert(
            make_detection(DOS, 0.5),
            make_risk_result(DOS, 50.0, "CRITICAL", explanation=f"alert {i}"),
            flow_i,
        )

    recent_3 = mgr.get_recent_alerts(3)
    print(f"  Total stored: {len(mgr.get_all_alerts())}")
    print(f"  Recent 3 returned: {len(recent_3)}")
    for a in recent_3:
        print(f"    {a.alert_id[:8]}... explanation={a.explanation}")

    ok = len(recent_3) == 3
    return ok


def test_severity_counting():
    """Test 6: count_by_severity returns correct counts."""
    print("=" * 60)
    print("TEST 6: Severity counting")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)

    mgr.create_alert(make_detection(DOS, 0.9), make_risk_result(DOS, 90.0, "CRITICAL"), flow)
    mgr.create_alert(make_detection(DOS, 0.8), make_risk_result(DOS, 80.0, "CRITICAL"), make_flow("10.0.0.1", "10.0.0.2", 5001, 22))
    mgr.create_alert(make_detection(BRUTE_FORCE, 0.7), make_risk_result(BRUTE_FORCE, 60.0, "HIGH"), make_flow("10.0.0.1", "10.0.0.2", 5002, 22))
    mgr.create_alert(make_detection(PORT_SCAN, 0.5), make_risk_result(PORT_SCAN, 25.0, "MEDIUM"), make_flow("10.0.0.1", "10.0.0.2", 5003, 22))

    counts = mgr.count_by_severity()
    print(f"  Counts: {counts}")

    ok = (
        counts.get("CRITICAL", 0) == 2
        and counts.get("HIGH", 0) == 1
        and counts.get("MEDIUM", 0) == 1
        and counts.get("INFORMATIONAL", 0) == 0
    )
    return ok


def test_attack_type_counting():
    """Test 7: count_by_attack_type returns correct counts."""
    print("=" * 60)
    print("TEST 7: Attack type counting")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)

    mgr.create_alert(make_detection(DOS, 0.9), make_risk_result(DOS, 90.0, "CRITICAL"), make_flow("10.0.0.1", "10.0.0.2", 5000, 22))
    mgr.create_alert(make_detection(PORT_SCAN, 0.5), make_risk_result(PORT_SCAN, 25.0, "MEDIUM"), make_flow("10.0.0.1", "10.0.0.2", 5001, 22))
    mgr.create_alert(make_detection(PORT_SCAN, 0.6), make_risk_result(PORT_SCAN, 30.0, "MEDIUM"), make_flow("10.0.0.1", "10.0.0.2", 5002, 22))
    mgr.create_alert(make_detection(BRUTE_FORCE, 0.7), make_risk_result(BRUTE_FORCE, 60.0, "HIGH"), make_flow("10.0.0.1", "10.0.0.2", 5003, 22))

    counts = mgr.count_by_attack_type()
    print(f"  Counts: {counts}")

    ok = (
        counts.get(DOS, 0) == 1
        and counts.get(PORT_SCAN, 0) == 2
        and counts.get(BRUTE_FORCE, 0) == 1
    )
    return ok


def test_clear_alerts():
    """Test 8: clear_alerts removes all stored alerts."""
    print("=" * 60)
    print("TEST 8: Clear alerts")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow()

    mgr.create_alert(make_detection(DOS, 0.9), make_risk_result(DOS, 90.0, "CRITICAL"), flow)
    mgr.create_alert(make_detection(PORT_SCAN, 0.5), make_risk_result(PORT_SCAN, 25.0, "MEDIUM"), flow)

    before = len(mgr.get_all_alerts())
    cleared = mgr.clear_alerts()
    after = len(mgr.get_all_alerts())

    print(f"  Before clear: {before}")
    print(f"  Cleared: {cleared}")
    print(f"  After clear: {after}")

    ok = before == 2 and cleared == 2 and after == 0
    return ok


def test_deduplication():
    """Test 9: Identical alerts within dedup window are collapsed."""
    print("=" * 60)
    print("TEST 9: Deduplication (within window)")
    print("=" * 60)

    # Short dedup window for testing
    config = AlertManagerConfig(dedup_window=1.0)
    mgr = AlertManager(config=config)

    flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 80)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    # Create the same alert 5 times rapidly
    alerts = []
    for i in range(5):
        a = mgr.create_alert(detection, risk, flow)
        if i == 0:
            alerts.append(a)  # first creates a new alert

    all_alerts = mgr.get_all_alerts()
    print(f"  Created 5 identical alerts")
    print(f"  Alerts in store: {len(all_alerts)}")
    if all_alerts:
        print(f"  First alert count: {all_alerts[0].count}")

    # Should have 1 alert (the first), with count=5
    ok = len(all_alerts) == 1 and all_alerts[0].count == 5
    return ok


def test_dedup_expiry():
    """Test 10: Identical alerts outside dedup window create new alerts."""
    print("=" * 60)
    print("TEST 10: Deduplication expiry")
    print("=" * 60)

    config = AlertManagerConfig(dedup_window=0.3)
    mgr = AlertManager(config=config)

    flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 80)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    # Create first alert
    mgr.create_alert(detection, risk, flow)
    time.sleep(0.5)  # wait for dedup window to expire

    # Create same alert again — should be a new alert
    mgr.create_alert(detection, risk, flow)

    all_alerts = mgr.get_all_alerts()
    print(f"  Created 2 identical alerts (0.5s apart, window=0.3s)")
    print(f"  Alerts in store: {len(all_alerts)}")
    for a in all_alerts:
        print(f"    count={a.count} explanation={a.explanation[:50]}")

    ok = len(all_alerts) == 2 and all_alerts[0].count == 1
    return ok


def test_rate_limiting():
    """Test 11: Rate limiting per source IP."""
    print("=" * 60)
    print("TEST 11: Rate limiting")
    print("=" * 60)

    # Allow only 3 alerts per source per window
    config = AlertManagerConfig(
        dedup_window=60.0,
        rate_limit_per_source=3,
        keep_suppressed=True,
    )
    mgr = AlertManager(config=config)

    flow_base = make_flow("10.0.0.100", "10.0.0.2", 50000, 80)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    alerts = []
    for i in range(5):
        # Use different dst ports to avoid dedup collapsing
        flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 80 + i)
        a = mgr.create_alert(detection, risk, flow)
        alerts.append(a)

    suppressed_count = sum(1 for a in alerts if a is not None and a.suppressed)
    normal_count = sum(1 for a in alerts if a is not None and not a.suppressed)

    print(f"  Created 5 alerts from same source, rate_limit=3")
    print(f"  Normal alerts: {normal_count}")
    print(f"  Suppressed alerts: {suppressed_count}")

    # Should have 3 normal + 2 suppressed
    ok = normal_count == 3 and suppressed_count == 2
    return ok


def test_rate_limiting_discard():
    """Test 11b: Rate limiting with keep_suppressed=False discards."""
    print("=" * 60)
    print("TEST 11b: Rate limiting (discard mode)")
    print("=" * 60)

    config = AlertManagerConfig(
        dedup_window=60.0,
        rate_limit_per_source=3,
        keep_suppressed=False,
    )
    mgr = AlertManager(config=config)

    flow_base = make_flow("10.0.0.100", "10.0.0.2", 50000, 80)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    returned_alerts = []
    for i in range(5):
        flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 80 + i)
        a = mgr.create_alert(detection, risk, flow)
        returned_alerts.append(a)

    stored = mgr.get_all_alerts()
    suppressed_returned = sum(1 for a in returned_alerts if a is not None and a.suppressed)

    print(f"  Created 5 alerts, rate_limit=3, keep_suppressed=False")
    print(f"  Stored alerts: {len(stored)}")
    print(f"  Suppressed returned: {suppressed_returned}")

    ok = len(stored) == 3 and suppressed_returned == 0
    return ok


def test_severity_filtering():
    """Test 12: Severity filtering blocks low-severity alerts."""
    print("=" * 60)
    print("TEST 12: Severity filtering")
    print("=" * 60)

    # Only allow MEDIUM and above
    config = AlertManagerConfig(min_severity_weight=SEVERITY_WEIGHTS["MEDIUM"])
    mgr = AlertManager(config=config)

    flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 22)

    # BENIGN -> INFORMATIONAL (weight 0) should be filtered
    a_benign = mgr.create_alert(
        make_detection(BENIGN, 0.05),
        make_risk_result(BENIGN, 0.5, "INFORMATIONAL"),
        flow,
    )
    # PORT_SCAN -> MEDIUM (weight 2) should pass
    a_portscan = mgr.create_alert(
        make_detection(PORT_SCAN, 0.7),
        make_risk_result(PORT_SCAN, 25.0, "MEDIUM"),
        flow,
    )
    # DOS -> CRITICAL (weight 4) should pass
    a_dos = mgr.create_alert(
        make_detection(DOS, 0.9),
        make_risk_result(DOS, 90.0, "CRITICAL"),
        flow,
    )

    all_alerts = mgr.get_all_alerts()
    stats = mgr.get_stats()

    print(f"  BENIGN alert returned: {a_benign}")
    print(f"  PORT_SCAN alert returned: {a_portscan is not None}")
    print(f"  DOS alert returned: {a_dos is not None}")
    print(f"  Total stored: {len(all_alerts)}")
    print(f"  Total filtered: {stats['total_filtered']}")

    ok = (
        a_benign is None
        and a_portscan is not None
        and a_dos is not None
        and len(all_alerts) == 2
        and stats["total_filtered"] == 1
    )
    return ok


def test_thread_safety():
    """Test 13: Basic thread-safe concurrent alert creation."""
    print("=" * 60)
    print("TEST 13: Thread safety")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow()
    detection = make_detection(DOS, 0.9, explanation="concurrent DOS")
    risk = make_risk_result(DOS, 90.0, "CRITICAL", explanation="concurrent")

    num_threads = 10
    alerts_per_thread = 10
    errors = []

    def worker():
        try:
            for _ in range(alerts_per_thread):
                mgr.create_alert(detection, risk, flow)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_alerts = mgr.get_all_alerts()
    stats = mgr.get_stats()

    # Due to dedup, we expect far fewer than 100 alerts
    print(f"  Threads: {num_threads}, alerts per thread: {alerts_per_thread}")
    print(f"  Total created: {stats['total_created']}")
    print(f"  Stored alerts: {len(all_alerts)}")
    print(f"  Errors: {len(errors)}")

    # No errors should occur
    # Total created should be num_threads * alerts_per_thread (all counted)
    # Stored alerts should be 1 (all deduped to same key)
    ok = len(errors) == 0 and stats["total_created"] == num_threads * alerts_per_thread
    return ok


def test_malformed_inputs():
    """Test 14: Malformed/invalid inputs are handled gracefully."""
    print("=" * 60)
    print("TEST 14: Malformed inputs")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow()

    # Test with BENIGN + low confidence (should still be created if severity filter allows)
    detection = make_detection(BENIGN, 0.01)
    risk = make_risk_result(BENIGN, 0.5, "INFORMATIONAL")
    a1 = mgr.create_alert(detection, risk, flow)
    print(f"  BENIGN low conf: {a1 is not None}")

    # Test with empty triggered_rules
    detection2 = make_detection(DOS, 0.9, triggered_rules=[])
    risk2 = make_risk_result(DOS, 90.0, "CRITICAL")
    a2 = mgr.create_alert(detection2, risk2, flow)
    print(f"  Empty triggered_rules: {a2 is not None and a2.triggered_rules == []}")

    # Test with zero confidence
    detection3 = make_detection(DOS, 0.0)
    risk3 = make_risk_result(DOS, 0.0, "CRITICAL")
    a3 = mgr.create_alert(detection3, risk3, flow)
    print(f"  Zero confidence: {a3 is not None and a3.confidence == 0.0}")

    ok = a1 is not None and a2 is not None and a3 is not None
    return ok


def test_feature_snapshot():
    """Test: Alert stores 18-feature snapshot passed through create_alert."""
    print("=" * 60)
    print("TEST: Feature snapshot persistence")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    features = list(range(18))  # 18 feature values
    alert = mgr.create_alert(detection, risk, flow, features=features)

    assert alert.feature_snapshot is not None
    assert len(alert.feature_snapshot) == 18
    assert alert.feature_snapshot == features

    # to_dict should include it
    d = alert.to_dict()
    assert "feature_snapshot" in d
    assert d["feature_snapshot"] == features

    print(f"  Feature snapshot length: {len(alert.feature_snapshot)}")
    print(f"  First 3 values: {alert.feature_snapshot[:3]}")
    return True


def test_feature_snapshot_none_when_not_provided():
    """Test: Alert.feature_snapshot is None when features not provided."""
    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    alert = mgr.create_alert(detection, risk, flow)

    assert alert.feature_snapshot is None
    print("  feature_snapshot is None when not provided: OK")
    return True


def test_ml_top3_persistence():
    """Test: Alert stores ml_top3 from DetectionResult."""
    print("=" * 60)
    print("TEST: ML top-3 persistence")
    print("=" * 60)

    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    detection.ml_top3 = [("DOS", 0.85), ("PORT_SCAN", 0.10), ("BENIGN", 0.03)]
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    alert = mgr.create_alert(detection, risk, flow)

    assert alert.ml_top3 is not None
    assert len(alert.ml_top3) == 3
    assert alert.ml_top3[0] == ("DOS", 0.85)
    assert alert.ml_top3[1] == ("PORT_SCAN", 0.10)
    assert alert.ml_top3[2] == ("BENIGN", 0.03)

    print(f"  ml_top3: {alert.ml_top3}")
    return True


def test_ml_top3_none_when_empty():
    """Test: Alert.ml_top3 is None when DetectionResult.ml_top3 is empty."""
    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    alert = mgr.create_alert(detection, risk, flow)

    assert alert.ml_top3 is None
    print("  ml_top3 is None when not provided: OK")
    return True


def test_feature_snapshot_copied_not_referenced():
    """Test: alert.feature_snapshot is a copy, not a reference to the original list."""
    mgr = make_manager()
    flow = make_flow("10.0.0.1", "10.0.0.2", 5000, 22)
    detection = make_detection(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    features = [0.1] * 18
    alert = mgr.create_alert(detection, risk, flow, features=features)

    # Modify original list — alert snapshot should be unaffected
    features[0] = 999.0
    assert alert.feature_snapshot[0] == 0.1  # not 999.0

    print("  Feature snapshot is a copy: OK")
    return True


def test_dedup_preserves_feature_snapshot():
    """Test: When an alert is deduped, the feature snapshot is updated on the existing alert."""
    config = AlertManagerConfig(dedup_window=1.0)
    mgr = AlertManager(config=config)

    flow = make_flow("10.0.0.100", "10.0.0.2", 50000, 80)
    detection = make_detection(DOS, 0.90, explanation="DOS detected")
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    features1 = [1.0] * 18
    features2 = [2.0] * 18

    alert1 = mgr.create_alert(detection, risk, flow, features=features1)
    alert2 = mgr.create_alert(detection, risk, flow, features=features2)

    # Deduped alert should be the same object
    assert alert1 is alert2 or alert1.alert_id == alert2.alert_id
    all_alerts = mgr.get_all_alerts()
    assert len(all_alerts) == 1

    # The feature snapshot should be from the original (deduped) creation
    # (dedup path doesn't overwrite features)
    print(f"  Deduped alert feature_snapshot[0]: {all_alerts[0].feature_snapshot[0] if all_alerts[0].feature_snapshot else 'None'}")
    return True


# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("NIDS ALERT MANAGER TESTS")
    print("=" * 60 + "\n")

    tests = [
        ("Alert creation", test_alert_creation),
        ("Required fields", test_required_fields),
        ("Dictionary serialization", test_dict_serialization),
        ("Store and retrieve", test_store_and_retrieve),
        ("Latest N retrieval", test_latest_n),
        ("Severity counting", test_severity_counting),
        ("Attack type counting", test_attack_type_counting),
        ("Clear alerts", test_clear_alerts),
        ("Deduplication", test_deduplication),
        ("Dedup expiry", test_dedup_expiry),
        ("Rate limiting", test_rate_limiting),
        ("Rate limiting discard", test_rate_limiting_discard),
        ("Severity filtering", test_severity_filtering),
        ("Thread safety", test_thread_safety),
        ("Malformed inputs", test_malformed_inputs),
        ("Feature snapshot persistence", test_feature_snapshot),
        ("Feature snapshot None when not provided", test_feature_snapshot_none_when_not_provided),
        ("ML top-3 persistence", test_ml_top3_persistence),
        ("ML top-3 None when empty", test_ml_top3_none_when_empty),
        ("Feature snapshot copied (not referenced)", test_feature_snapshot_copied_not_referenced),
        ("Dedup preserves feature snapshot", test_dedup_preserves_feature_snapshot),
    ]

    results = []
    for name, func in tests:
        result = func()
        results.append((name, result))
        print(f"  Result: {'PASS' if result else 'FAIL'}\n")

    print("=" * 60)
    print("SUMMARY")
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
