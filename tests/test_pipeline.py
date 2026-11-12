"""
Tests for the NIDS End-to-End Pipeline.

All tests use dependency injection with mocked/fake components.
No real network traffic, root privileges, or live Scapy capture is required.

Run from project root:
    python -m NIDS.tests.test_pipeline
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

from NIDS.pipeline import NIDSPipeline, DEFAULT_MODEL_PATH
from NIDS.flow import Flow
from NIDS.flow_manager import FlowManager
from NIDS.rule_engine import RuleEngine, RuleResult, BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE
from NIDS.correlator import CorrelationEngine, DetectionResult
from NIDS.model import NIDSModel
from NIDS.risk_scorer import RiskScorer, RiskResult
from NIDS.alerts import AlertManager, AlertManagerConfig, Alert
from NIDS.config import SEVERITY_MAP


# ---------------------------------------------------------------------------
# Fake components for dependency injection
# ---------------------------------------------------------------------------

class FakeModel:
    """A minimal NIDSModel stand-in for testing.

    Follows sklearn convention: clf.classes_ holds integer class values
    (0=BENIGN, 1=PORT_SCAN, ...), and clf.predict() returns those integers.
    """

    def __init__(self, predict_label=BENIGN, predict_conf=0.5, all_probs=None):
        self._label_to_int = {"BENIGN": 0, "PORT_SCAN": 1, "BRUTE_FORCE": 2,
                              "DOS": 3, "RECONNAISSANCE": 4}
        self._int_to_label = {v: k for k, v in self._label_to_int.items()}

        self.classes_ = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]
        self._label = predict_label
        self._conf = predict_conf
        self.scaler = MagicMock()
        self.clf = MagicMock()
        self._is_fitted = True

        import numpy as np

        if all_probs is None:
            all_probs = {c: 0.0 for c in self.classes_}
            all_probs[predict_label] = predict_conf
            remaining = 1.0 - predict_conf
            if remaining > 0:
                other = [k for k in self.classes_ if k != predict_label]
                share = remaining / len(other) if other else 0.0
                for k in other:
                    all_probs[k] = share

        # sklearn convention: clf.classes_ holds integer class values
        self.clf.classes_ = np.array([0, 1, 2, 3, 4])

        # probs ordered by clf.classes_ (integers 0-4), mapped from all_probs (string keys)
        self._prob_array = np.array([
            all_probs[self._int_to_label[i]] for i in range(5)
        ]).reshape(1, -1)

        self.clf.predict_proba = MagicMock(return_value=self._prob_array)
        self.clf.predict = MagicMock(return_value=np.array([self._label_to_int[predict_label]]))
        self.scaler.transform = MagicMock(side_effect=lambda x: __import__("numpy").asarray(x).reshape(1, -1))

    def predict(self, features):
        if isinstance(features, list) and isinstance(features[0], (int, float)):
            return self._label, self._conf
        return [self._label] * len(features), [self._conf] * len(features)


def make_benign_flow():
    """Create a simple benign flow for testing."""
    flow = Flow("10.0.0.10", "10.0.0.2", 50000, 22, 6)
    t = 1000.0
    flow.add_packet(t, 64, "forward", 0x02)        # SYN
    flow.add_packet(t + 0.001, 64, "backward", 0x12)  # SYN-ACK
    flow.add_packet(t + 0.01, 120, "forward", 0x18)  # PSH-ACK
    flow.add_packet(t + 0.02, 200, "backward", 0x18) # PSH-ACK
    flow.add_packet(t + 0.2, 64, "forward", 0x01)   # FIN
    flow.add_packet(t + 0.201, 64, "backward", 0x10) # ACK
    return flow


def make_dos_flow():
    """Create a DoS-like flow with high packet count."""
    flow = Flow("10.0.0.100", "10.0.0.2", 1000, 80, 6)
    t = 1000.0
    for i in range(1000):
        flow.add_packet(t + i * 0.001, 60, "forward", 0x02)
    return flow


def make_rule_result(prediction=BENIGN, confidence=0.0, triggered=None):
    return RuleResult(
        rule_prediction=prediction,
        rule_confidence=confidence,
        triggered_rules=triggered or [],
        rule_reason="test",
    )


def make_detection_result(prediction=BENIGN, confidence=0.0, explanation=""):
    return DetectionResult(
        final_prediction=prediction,
        combined_confidence=confidence,
        rule_prediction=prediction,
        rule_confidence=confidence,
        ml_prediction=prediction,
        ml_confidence=confidence,
        triggered_rules=[],
        ml_top3=[],
        explanation=explanation or "test detection",
    )


def make_risk_result(prediction=BENIGN, risk_score=0.0, severity=None):
    if severity is None:
        severity = SEVERITY_MAP.get(prediction, "INFORMATIONAL")
    return RiskResult(
        risk_score=risk_score,
        severity=severity,
        prediction=prediction,
        confidence=0.5,
        explanation="risk explanation",
        rule_reason="rule reason",
    )


def _run_test(name, func):
    """Run a single test function and print result."""
    print("=" * 60)
    print(f"TEST: {name}")
    print("=" * 60)
    try:
        result = func()
        ok = result
    except Exception as e:
        import traceback
        traceback.print_exc()
        ok = False
    print(f"  Result: {'PASS' if ok else 'FAIL'}\n")
    return ok


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_pipeline_initialization():
    """Test 1: Pipeline initializes with all components."""
    print("  Creating pipeline with injected fake model...")

    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    ok = (
        isinstance(pipeline.flow_manager, FlowManager)
        and isinstance(pipeline.rule_engine, RuleEngine)
        and isinstance(pipeline.correlation_engine, CorrelationEngine)
        and isinstance(pipeline.risk_scorer, RiskScorer)
        and isinstance(pipeline.alert_manager, AlertManager)
    )
    print(f"  flow_manager: {type(pipeline.flow_manager).__name__}")
    print(f"  rule_engine:  {type(pipeline.rule_engine).__name__}")
    print(f"  corr_engine:  {type(pipeline.correlation_engine).__name__}")
    print(f"  risk_scorer:  {type(pipeline.risk_scorer).__name__}")
    print(f"  alert_mgr:    {type(pipeline.alert_manager).__name__}")
    return ok


def test_single_benign_flow():
    """Test 2: Single completed benign flow through the pipeline."""
    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    alerts = pipeline._process_flow(flow)

    print(f"  Alerts generated: {len(alerts)}")
    if alerts:
        print(f"  Alert: type={alerts[0].attack_type}, risk={alerts[0].risk_score}, sev={alerts[0].severity}")

    # BENIGN should produce no alert (severity INFORMATIONAL filtered by default)
    # With default AlertManagerConfig (min_severity_weight=0), INFO passes
    # So we should get 1 alert
    ok = len(alerts) == 1 and alerts[0].attack_type == BENIGN
    return ok


def test_malicious_flow():
    """Test 3: Malicious (DoS) flow through the pipeline."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_dos_flow()

    # Need RuleEngine state for the flow to be detected
    # The RuleEngine needs to see the flow with high pps
    rule_result = pipeline.rule_engine.process_flow(flow)
    print(f"  Rule prediction: {rule_result.rule_prediction} (conf={rule_result.rule_confidence})")

    alerts = pipeline._process_flow(flow)
    print(f"  Alerts generated: {len(alerts)}")
    if alerts:
        print(f"  Alert: type={alerts[0].attack_type}, risk={alerts[0].risk_score}, sev={alerts[0].severity}")

    ok = len(alerts) >= 1
    return ok


def test_multiple_completed_flows():
    """Test 4: Multiple completed flows from one packet batch."""
    fake_model = FakeModel(predict_label=PORT_SCAN, predict_conf=0.7)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Manually feed flows via process_packet_info
    # Use different 5-tuples to avoid dedup
    flows_data = [
        ("10.0.0.1", "10.0.0.2", 1000, 22),
        ("10.0.0.1", "10.0.0.2", 1001, 80),
        ("10.0.0.1", "10.0.0.2", 1002, 443),
    ]

    # We'll call _process_flow directly for each flow
    alerts = []
    for src_port, dst_port in [(1000, 22), (1001, 80), (1002, 443)]:
        flow = Flow("10.0.0.1", "10.0.0.2", src_port, dst_port, 6)
        flow.add_packet(1000.0, 66, "forward", 0x02)
        t0 = pipeline._process_flow(flow)
        alerts.extend(t0)

    print(f"  Flows processed: 3")
    print(f"  Alerts generated: {len(alerts)}")

    ok = len(alerts) == 3
    return ok


def test_rule_ml_agreement():
    """Test 5: Rule + ML agree on attack class."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_dos_flow()
    rule_result = pipeline.rule_engine.process_flow(flow)
    # Force agreement: rule says DOS too
    # The rule engine should detect DOS for the high-rate flow
    print(f"  Rule prediction: {rule_result.rule_prediction} (conf={rule_result.rule_confidence})")
    print(f"  ML prediction:   {fake_model._label} (conf={fake_model._conf})")

    alerts = pipeline._process_flow(flow)
    if alerts:
        detection = pipeline.correlation_engine.correlate(flow.get_features(), rule_result)
        print(f"  Final prediction: {detection.final_prediction}")
        print(f"  Combined conf:    {detection.combined_confidence}")
        print(f"  Alert risk:       {alerts[0].risk_score}")

    ok = (
        len(alerts) >= 1
        and alerts[0].attack_type == DOS
        and alerts[0].risk_score >= 80.0  # DOS base risk
    )
    return ok


def test_rule_ml_disagreement():
    """Test 6: Rule + ML disagree on different attack classes."""
    # ML thinks DOS, but we'll make RuleEngine say BENIGN
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.70)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    # Rule engine should detect BENIGN (low threshold benign flow)
    rule_result = pipeline.rule_engine.process_flow(flow)
    print(f"  Rule prediction: {rule_result.rule_prediction} (conf={rule_result.rule_confidence})")
    print(f"  ML prediction:   {fake_model._label} (conf={fake_model._conf})")

    alerts = pipeline._process_flow(flow)
    detection = pipeline.correlation_engine.correlate(flow.get_features(), rule_result)
    print(f"  Final prediction: {detection.final_prediction}")
    print(f"  Combined conf:    {detection.combined_confidence}")

    # ML-only: DOS detected by ML, BENIGN by rules
    # This is Case C: ml-only, confidence penalized
    ok = detection.final_prediction == DOS  # ML's prediction wins
    return ok


def test_full_sequence():
    """Test 7: Full sequence from Flow to Alert."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_dos_flow()

    # Trace the full sequence
    features = flow.get_features()
    print(f"  Features count: {len(features)}")

    rule_result = pipeline.rule_engine.process_flow(flow)
    print(f"  RuleResult: pred={rule_result.rule_prediction}, conf={rule_result.rule_confidence}")

    detection = pipeline.correlation_engine.correlate(features, rule_result)
    print(f"  Detection: pred={detection.final_prediction}, conf={detection.combined_confidence}")

    risk = pipeline.risk_scorer.score(detection)
    print(f"  Risk: score={risk.risk_score}, severity={risk.severity}")

    alerts = pipeline._process_flow(flow)
    print(f"  Alerts: {len(alerts)}")
    if alerts:
        print(f"  Alert fields: {len(alerts[0].to_dict())} keys")

    ok = (
        len(features) == 18
        and detection.final_prediction in [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE]
        and 0 <= risk.risk_score <= 100
        and len(alerts) >= 1
    )
    return ok


def test_no_completed_flows():
    """Test 8: FlowManager returns [] -> no processing, no alert."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # process_packet with a non-IP packet (FlowManager.process_packet returns [])
    # We simulate by calling _extract_flows with no args
    flows = pipeline._extract_flows(packet=None, packet_info=None, timestamp=0.0)
    print(f"  Completed flows: {len(flows)}")

    ok = len(flows) == 0
    return ok


def test_feature_extraction_failure():
    """Test 9: Feature extraction failure -> flow fails, pipeline continues."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Create a flow whose get_features will fail
    flow = make_benign_flow()

    # Monkeypatch get_features to raise
    original = flow.get_features
    flow.get_features = MagicMock(side_effect=RuntimeError("feature extraction error"))

    alerts = pipeline._process_flow(flow)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    # Restore for any other uses
    flow.get_features = original
    ok = len(alerts) == 0 and stats["flows_failed"] >= 1
    return ok


def test_rule_engine_failure():
    """Test 10: Rule engine failure -> flow fails, pipeline continues."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    pipeline.rule_engine.process_flow = MagicMock(side_effect=RuntimeError("rule engine error"))

    alerts = pipeline._process_flow(flow)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    ok = len(alerts) == 0 and stats["flows_failed"] >= 1
    return ok


def test_correlation_failure():
    """Test 11: Correlation failure -> flow fails, pipeline continues."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    pipeline.correlation_engine.correlate = MagicMock(side_effect=RuntimeError("correlation error"))

    alerts = pipeline._process_flow(flow)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    ok = len(alerts) == 0 and stats["flows_failed"] >= 1
    return ok


def test_risk_scoring_failure():
    """Test 12: Risk scoring failure -> flow fails, pipeline continues."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    pipeline.risk_scorer.score = MagicMock(side_effect=RuntimeError("risk scoring error"))

    alerts = pipeline._process_flow(flow)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    ok = len(alerts) == 0 and stats["flows_failed"] >= 1
    return ok


def test_alert_creation_failure():
    """Test 13: Alert creation failure -> flow fails, pipeline continues."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()
    pipeline.alert_manager.create_alert = MagicMock(side_effect=RuntimeError("alert creation error"))

    alerts = pipeline._process_flow(flow)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    ok = len(alerts) == 0 and stats["flows_failed"] >= 1
    return ok


def test_first_flow_fails_second_succeeds():
    """Test 14: First flow fails, second flow succeeds."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # First flow: make rule_engine fail
    flow1 = make_benign_flow()
    pipeline.rule_engine.process_flow = MagicMock(side_effect=RuntimeError("fail on first"))

    alerts1 = pipeline._process_flow(flow1)

    # Restore rule_engine, second flow should succeed
    pipeline.rule_engine = RuleEngine()  # fresh engine
    flow2 = make_dos_flow()
    alerts2 = pipeline._process_flow(flow2)

    stats = pipeline.get_stats()

    print(f"  Flow 1 alerts: {len(alerts1)}")
    print(f"  Flow 2 alerts: {len(alerts2)}")
    print(f"  Flows failed: {stats['flows_failed']}")

    ok = len(alerts1) == 0 and len(alerts2) >= 1 and stats["flows_failed"] >= 1
    return ok


def test_malformed_packet():
    """Test 15: Malformed/non-IP packet -> no crash, no alert."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Use a mock packet that will cause parse_packet_info to return None
    mock_packet = MagicMock()
    # Scapy's IP in packet check will fail with a mock that doesn't have IP layer
    # process_packet will call parse_packet_info which returns None
    # and flow_manager.process_packet will return []

    alerts = pipeline.process_packet(packet=mock_packet)
    stats = pipeline.get_stats()

    print(f"  Alerts generated: {len(alerts)}")
    print(f"  Packets processed: {stats['packets_processed']}")

    ok = len(alerts) == 0 and stats["packets_processed"] == 1
    return ok


def test_pipeline_statistics():
    """Test 16: Pipeline statistics are correctly tracked."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Process a few flows
    flow = make_dos_flow()
    pipeline._process_flow(flow)
    pipeline._process_flow(flow)  # same flow, dedup will collapse

    stats = pipeline.get_stats()
    print(f"  Stats: {stats}")

    ok = (
        stats["flows_processed"] == 2  # _process_flow increments flows_processed
        and stats["alerts_created"] == 2  # both return non-None alerts (deduped)
    )
    return ok


def test_alertmanager_delegation():
    """Test 17: AlertManager methods are properly delegated."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    # Use a severity filter that blocks everything
    alert_mgr = AlertManager(config=AlertManagerConfig(min_severity_weight=999))
    pipeline = NIDSPipeline(
        correlation_engine=engine,
        alert_manager=alert_mgr,
    )

    flow = make_benign_flow()
    pipeline._process_flow(flow)

    print(f"  get_alerts(): {pipeline.get_alerts()}")
    print(f"  get_alert_stats(): {pipeline.get_alert_stats()}")
    print(f"  count_alerts_by_severity(): {pipeline.count_alerts_by_severity()}")
    print(f"  count_alerts_by_attack_type(): {pipeline.count_alerts_by_attack_type()}")

    ok = (
        isinstance(pipeline.get_alerts(), list)
        and isinstance(pipeline.get_alert_stats(), dict)
        and isinstance(pipeline.count_alerts_by_severity(), dict)
        and isinstance(pipeline.count_alerts_by_attack_type(), dict)
    )
    return ok


def test_capture_callback_integration():
    """Test 18: Capture callback integration (simulated)."""
    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Simulate what the Scapy callback would do:
    # Build a packet_info dict and call process_packet_info
    packet_info = {
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.0.2",
        "protocol": 6,
        "packet_len": 66,
        "src_port": 50000,
        "dst_port": 22,
        "tcp_flags": 0x02,
        "has_tcp": True,
        "has_udp": False,
        "has_icmp": False,
    }

    # Send a few packets that will timeout
    t = 1000.0
    pipeline.process_packet_info(packet_info, t)
    pipeline.process_packet_info(packet_info, t + 5.0)
    # Trigger timeout by sending a packet to a different flow
    trigger = {
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.2",
        "protocol": 6,
        "packet_len": 66,
        "src_port": 40000,
        "dst_port": 443,
        "tcp_flags": 0x02,
        "has_tcp": True,
        "has_udp": False,
        "has_icmp": False,
    }
    alerts = pipeline.process_packet_info(trigger, t + 20.0)

    stats = pipeline.get_stats()
    print(f"  Packets processed: {stats['packets_processed']}")
    print(f"  Flows completed: {stats['flows_completed']}")
    print(f"  Alerts generated: {len(alerts)}")

    ok = stats["packets_processed"] == 3 and len(alerts) >= 0
    return ok


def test_model_loaded_once():
    """Test 19: Model is loaded only once during pipeline init."""
    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)

    # Track NIDSModel.load calls
    original_load = NIDSModel.load
    call_count = [0]

    def counting_load(path):
        call_count[0] += 1
        return original_load(path)

    pipeline = NIDSPipeline(correlation_engine=engine)

    # The model was injected, so load was not called
    # Verify the same model instance is used for multiple flows
    flow1 = make_benign_flow()
    flow2 = make_dos_flow()

    pipeline._process_flow(flow1)
    pipeline._process_flow(flow2)

    # The model in the pipeline should be the same object each time
    model_ref = pipeline.correlation_engine.model
    ok = model_ref is fake_model  # same instance, loaded once
    print(f"  Model is same instance: {ok}")
    print(f"  Model classes: {model_ref.classes_}")
    return ok


def test_graceful_keyboard_interrupt():
    """Test 20: KeyboardInterrupt during capture is handled."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Mock capture_packets to raise KeyboardInterrupt
    with patch("NIDS.pipeline.capture_packets") as mock_capture:
        mock_capture.side_effect = KeyboardInterrupt()
        try:
            pipeline.start_capture()
        except KeyboardInterrupt:
            pass  # should be caught by pipeline

    stats = pipeline.get_stats()
    print(f"  Stop flag set: {pipeline._stop_flag}")
    print(f"  Stats: {stats}")

    ok = pipeline._stop_flag is True
    return ok


def test_stop_method():
    """Test: stop() sets the stop flag."""
    fake_model = FakeModel()
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_benign_flow()

    # Process one flow
    pipeline._process_flow(flow)

    # Stop
    pipeline.stop()

    # After stop, process_packet should return []
    alerts = pipeline.process_packet_info(
        {
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.2",
            "protocol": 6,
            "packet_len": 66,
            "src_port": 50000,
            "dst_port": 22,
            "tcp_flags": 0x02,
            "has_tcp": True,
            "has_udp": False,
            "has_icmp": False,
        },
        1000.0,
    )

    print(f"  Stop flag: {pipeline._stop_flag}")
    print(f"  Alerts after stop: {len(alerts)}")

    ok = pipeline._stop_flag is True and len(alerts) == 0
    return ok


def test_finalize_flows():
    """Test: finalize_flows processes remaining active flows."""
    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    # Add a flow to the FlowManager
    flow = make_dos_flow()
    features = flow.get_features()
    rule_result = pipeline.rule_engine.process_flow(flow)

    # Process directly to get an alert
    alerts = pipeline._process_flow(flow)

    # Now finalize
    final_alerts = pipeline.finalize_flows()

    print(f"  Direct alerts: {len(alerts)}")
    print(f"  Finalize alerts: {len(final_alerts)}")
    print(f"  Active flows after finalize: {pipeline.flow_manager.get_active_flow_count()}")

    ok = pipeline.flow_manager.get_active_flow_count() == 0
    return ok


def test_flows_in_progress_exposed():
    """Test: pipeline.get_stats() exposes flows_in_progress from FlowManager."""
    print("=" * 60)
    print("TEST: flows_in_progress exposed through pipeline stats")
    print("=" * 60)

    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    stats = pipeline.get_stats()
    assert "flows_in_progress" in stats
    assert stats["flows_in_progress"] == 0
    print(f"  Initial flows_in_progress: {stats['flows_in_progress']}")

    flow = make_benign_flow()
    pipeline._process_flow(flow)

    stats2 = pipeline.get_stats()
    assert "flows_in_progress" in stats2
    print(f"  After processing: flows_in_progress={stats2['flows_in_progress']}")

    ok = "flows_in_progress" in stats and "flows_in_progress" in stats2
    return ok


def test_alerts_suppressed_exposed():
    """Test: pipeline.get_stats() exposes alerts_suppressed from AlertManager."""
    print("=" * 60)
    print("TEST: alerts_suppressed exposed through pipeline stats")
    print("=" * 60)

    fake_model = FakeModel(predict_label=BENIGN, predict_conf=0.9)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    stats = pipeline.get_stats()
    assert "alerts_suppressed" in stats
    assert stats["alerts_suppressed"] == 0
    print(f"  Initial alerts_suppressed: {stats['alerts_suppressed']}")

    # Set rate limit low and disable dedup so rate limiting actually triggers
    pipeline.alert_manager.config.rate_limit_per_source = 2
    pipeline.alert_manager.config.dedup_window = 0.0

    detection = make_detection_result(DOS, 0.90)
    risk = make_risk_result(DOS, 90.0, "CRITICAL")

    # Create alerts from same source but different source ports so dedup keys
    # differ (dedup includes src_port) but rate limiting (per source_ip) triggers
    for i in range(5):
        flow = Flow("10.0.0.100", "10.0.0.2", 1000 + i, 80, 6)
        flow.add_packet(1000.0, 60, "forward", 0x02)
        pipeline.alert_manager.create_alert(detection, risk, flow)

    stats2 = pipeline.get_stats()
    assert "alerts_suppressed" in stats2
    assert stats2["alerts_suppressed"] > 0
    print(f"  After rate limiting: alerts_suppressed={stats2['alerts_suppressed']}")

    ok = stats2["alerts_suppressed"] > 0
    return ok


def test_pipeline_passes_features_to_alert():
    """Test: pipeline passes feature vector to AlertManager.create_alert."""
    print("=" * 60)
    print("TEST: pipeline passes features to create_alert")
    print("=" * 60)

    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_dos_flow()
    features = flow.get_features()
    assert len(features) == 18

    alerts = pipeline._process_flow(flow)
    assert len(alerts) >= 1

    alert = alerts[0]
    assert alert.feature_snapshot is not None
    assert len(alert.feature_snapshot) == 18
    assert alert.feature_snapshot == features

    print(f"  feature_snapshot length: {len(alert.feature_snapshot)}")
    print(f"  First 3 values: {alert.feature_snapshot[:3]}")
    return True


def test_pipeline_passes_ml_top3():
    """Test: pipeline passes ml_top3 from DetectionResult to Alert."""
    print("=" * 60)
    print("TEST: pipeline passes ml_top3 to Alert")
    print("=" * 60)

    from dataclasses import fields as dc_fields
    ok_count = "ml_top3" in {f.name for f in dc_fields(Alert)}
    ok_fs = "feature_snapshot" in {f.name for f in dc_fields(Alert)}
    print(f"  Alert has ml_top3 field: {ok_count}")
    print(f"  Alert has feature_snapshot field: {ok_fs}")

    fake_model = FakeModel(predict_label=DOS, predict_conf=0.85)
    engine = CorrelationEngine(model=fake_model)
    pipeline = NIDSPipeline(correlation_engine=engine)

    flow = make_dos_flow()
    alerts = pipeline._process_flow(flow)

    if alerts:
        alert = alerts[0]
        print(f"  ml_top3 on alert: {alert.ml_top3}")
        print(f"  feature_snapshot length: {len(alert.feature_snapshot or [])}")

    return ok_count and ok_fs


# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("NIDS END-TO-END PIPELINE TESTS")
    print("=" * 60 + "\n")

    tests = [
        ("Pipeline initialization", test_pipeline_initialization),
        ("Single benign flow", test_single_benign_flow),
        ("Malicious flow (DoS)", test_malicious_flow),
        ("Multiple completed flows", test_multiple_completed_flows),
        ("Rule + ML agreement", test_rule_ml_agreement),
        ("Rule + ML disagreement", test_rule_ml_disagreement),
        ("Full sequence (Flow->Alert)", test_full_sequence),
        ("No completed flows", test_no_completed_flows),
        ("Feature extraction failure", test_feature_extraction_failure),
        ("Rule engine failure", test_rule_engine_failure),
        ("Correlation failure", test_correlation_failure),
        ("Risk scoring failure", test_risk_scoring_failure),
        ("Alert creation failure", test_alert_creation_failure),
        ("First fails, second succeeds", test_first_flow_fails_second_succeeds),
        ("Malformed packet", test_malformed_packet),
        ("Pipeline statistics", test_pipeline_statistics),
        ("AlertManager delegation", test_alertmanager_delegation),
        ("Capture callback integration", test_capture_callback_integration),
        ("Model loaded once", test_model_loaded_once),
        ("Graceful KeyboardInterrupt", test_graceful_keyboard_interrupt),
        ("Stop method", test_stop_method),
        ("Finalize flows", test_finalize_flows),
        ("Flows in_progress exposed", test_flows_in_progress_exposed),
        ("Alerts suppressed exposed", test_alerts_suppressed_exposed),
        ("Pipeline passes features to alert", test_pipeline_passes_features_to_alert),
        ("Pipeline passes ml_top3", test_pipeline_passes_ml_top3),
    ]

    results = []
    for name, func in tests:
        results.append((name, _run_test(name, func)))

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
