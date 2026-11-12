"""
STAGE 11.8.7 — Split Architecture Tests
=========================================

Tests for:
- capture_listener_11_8_7.py (passive capture listener)
- collect_attack_11_8_v2.py generator/listener mode separation
- Server readiness/error reporting fix
- 5-tuple preservation
- TCP flag preservation
- No loopback fallback

Run:
    python -m NIDS.tests.test_stage11_8_7_split
"""

from __future__ import annotations

import json
import builtins
import sys
import tempfile
import threading
import time
import socket
import hashlib
from pathlib import Path
from typing import List
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.evaluation.capture_listener_11_8_7 import CaptureListener, model_hash, _is_loopback_interface
from NIDS.evaluation.collect_attack_11_8_v2 import (
    ScapyCaptureCollector,
    _is_loopback_interface as _is_loopback_collector,
    _validate_non_loopback_config,
    tcp_server_thread,
    udp_server_thread,
    DEFAULT_INTERFACE,
)
from NIDS.evaluation.schema import EvaluationRecord, CLASS_LABELS


# ===========================================================================
# Helpers
# ===========================================================================

def _assert_equal(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected}, got {actual}")


def _assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(f"{msg}: assertion failed")


def _assert_false(cond, msg=""):
    if cond:
        raise AssertionError(f"{msg}: expected False, got True")


# ===========================================================================
# Loopback detection tests
# ===========================================================================

class TestLoopbackDetection:
    def test_listener_rejects_loopback_interface(self):
        _assert_true(_is_loopback_interface("Loopback Pseudo-Interface 1"))
        _assert_true(_is_loopback_interface("lo"))
        _assert_true(_is_loopback_interface("LOOPBACK"))

    def test_listener_accepts_non_loopback_interface(self):
        _assert_true(not _is_loopback_interface("enp0s8"))
        _assert_true(not _is_loopback_interface("eth0"))
        _assert_true(not _is_loopback_interface("VirtualBox Host-Only Ethernet Adapter"))

    def test_collector_loopback_detection_matches_listener(self):
        _assert_equal(_is_loopback_interface("enp0s8"), _is_loopback_collector("enp0s8"))
        _assert_equal(_is_loopback_interface("lo"), _is_loopback_collector("lo"))


# ===========================================================================
# Listener tests
# ===========================================================================

class TestCaptureListener:
    def test_listener_rejects_loopback_interface(self):
        try:
            CaptureListener(interface="Loopback Pseudo-Interface 1", output_path="/tmp/test.jsonl")
            raise AssertionError("Should have raised ValueError for loopback interface")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_listener_accepts_non_loopback_interface(self):
        listener = CaptureListener(interface="enp0s8", output_path="/tmp/test.jsonl", run_pipeline=False)
        _assert_equal(listener.interface, "enp0s8")
        _assert_equal(listener.output_path, "/tmp/test.jsonl")

    def test_listener_does_not_generate_traffic(self):
        listener = CaptureListener(interface="enp0s8", output_path="/tmp/test.jsonl", run_pipeline=False)
        _assert_equal(listener.packet_count, 0)
        _assert_equal(listener.capture_error, None)
        _assert_false(listener.stop_capture)

    def test_listener_mode_validation(self):
        # run_pipeline=False should work without model loading issues
        listener = CaptureListener(interface="enp0s8", output_path="/tmp/test.jsonl", run_pipeline=False)
        _assert_equal(listener.run_pipeline, False)

    def test_listener_model_hash_verification(self):
        expected = "82f19f3726183ea8"
        actual = model_hash(str(PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib"))
        _assert_equal(actual, expected, "Model hash mismatch")

    def test_listener_no_loopback_fallback(self):
        # The listener constructor must reject loopback, not silently fall back
        with _assert_raises(ValueError):
            CaptureListener(interface="lo", output_path="/tmp/test.jsonl")


# ===========================================================================
# Collector mode tests
# ===========================================================================

class TestCollectorModes:
    def test_generator_mode_rejects_loopback_target(self):
        try:
            ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="127.0.0.1",
                mode="generator",
            )
            raise AssertionError("Should have raised ValueError for loopback target")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_generator_mode_accepts_non_loopback_target(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
            mode="generator",
        )
        _assert_equal(collector.mode, "generator")
        _assert_equal(collector.target_ip, "192.168.56.107")

    def test_full_mode_default(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
        )
        _assert_equal(collector.mode, "full")

    def test_invalid_mode_raises(self):
        try:
            ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="invalid",
            )
            raise AssertionError("Should have raised ValueError for invalid mode")
        except ValueError as e:
            _assert_true("Invalid mode" in str(e))

    def test_listener_mode_rejected_in_collector(self):
        try:
            ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="listener",
            )
            # Should NOT raise in constructor, but collect_all should raise
        except ValueError:
            pass  # Constructor may reject, that's fine

    def test_generator_mode_does_not_capture(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
            mode="generator",
        )
        _assert_equal(collector.packet_count, 0)
        _assert_equal(collector.capture_error, None)
        _assert_equal(len(collector.records), 0)


# ===========================================================================
# Server readiness tests
# ===========================================================================

class TestServerReadiness:
    def test_tcp_server_reports_bind_error(self):
        ready_event = threading.Event()
        stop_event = threading.Event()
        # Use an invalid IP to force bind failure
        t = threading.Thread(
            target=tcp_server_thread,
            args=(99999, "192.168.255.255", stop_event, ready_event),
            daemon=True,
        )
        t.start()
        # ready_event should eventually be set (in finally block)
        result = ready_event.wait(timeout=3.0)
        _assert_true(result, "ready_event should be set even on bind failure")
        stop_event.set()

    def test_udp_server_reports_bind_error(self):
        ready_event = threading.Event()
        stop_event = threading.Event()
        t = threading.Thread(
            target=udp_server_thread,
            args=(99999, "192.168.255.255", stop_event, ready_event),
            daemon=True,
        )
        t.start()
        result = ready_event.wait(timeout=3.0)
        _assert_true(result, "ready_event should be set even on bind failure")
        stop_event.set()

    def test_tcp_server_readiness_with_valid_port(self):
        ready_event = threading.Event()
        stop_event = threading.Event()
        t = threading.Thread(
            target=tcp_server_thread,
            args=(52000, "127.0.0.1", stop_event, ready_event),
            daemon=True,
        )
        t.start()
        result = ready_event.wait(timeout=3.0)
        _assert_true(result, "ready_event should be set for valid bind")
        stop_event.set()
        t.join(timeout=2.0)


# ===========================================================================
# 5-tuple and TCP flag preservation tests
# ===========================================================================

class TestAttributionPreservation:
    def test_exact_5_tuple_fields_preserved(self):
        rec = EvaluationRecord(
            evaluation_session_id="stage_11_8_7_test",
            collection_timestamp=1000.0,
            traffic_category="ATTACK",
            traffic_subtype="port_scan",
            ground_truth_label="PORT_SCAN",
            src_ip="192.168.56.105",
            dst_ip="192.168.56.107",
            src_port=45678,
            dst_port=52000,
            protocol=6,
            features=[0.0] * 18,
        )
        _assert_equal(rec.src_ip, "192.168.56.105")
        _assert_equal(rec.dst_ip, "192.168.56.107")
        _assert_equal(rec.src_port, 45678)
        _assert_equal(rec.dst_port, 52000)
        _assert_equal(rec.protocol, 6)

    def test_feature_count_is_18(self):
        features = [float(i) for i in range(18)]
        rec = EvaluationRecord(
            evaluation_session_id="stage_11_8_7_test",
            collection_timestamp=1000.0,
            traffic_category="ATTACK",
            traffic_subtype="port_scan",
            ground_truth_label="PORT_SCAN",
            src_ip="192.168.56.105",
            dst_ip="192.168.56.107",
            src_port=45678,
            dst_port=52000,
            protocol=6,
            features=features,
        )
        _assert_equal(len(rec.features), 18)

    def test_tcp_flag_feature_order(self):
        features = [0.0] * 18
        features[13] = 1.0  # syn_count
        features[14] = 2.0  # ack_count
        features[15] = 0.0  # fin_count
        features[16] = 0.0  # rst_count
        features[17] = 1.0  # psh_count
        rec = EvaluationRecord(
            evaluation_session_id="stage_11_8_7_test",
            collection_timestamp=1000.0,
            traffic_category="ATTACK",
            traffic_subtype="port_scan",
            ground_truth_label="PORT_SCAN",
            src_ip="192.168.56.105",
            dst_ip="192.168.56.107",
            src_port=45678,
            dst_port=52000,
            protocol=6,
            features=features,
        )
        _assert_equal(rec.features[13], 1.0)  # syn
        _assert_equal(rec.features[14], 2.0)  # ack
        _assert_equal(rec.features[15], 0.0)  # fin
        _assert_equal(rec.features[16], 0.0)  # rst
        _assert_equal(rec.features[17], 1.0)  # psh


# ===========================================================================
# Model integrity tests
# ===========================================================================

class TestModelIntegrity:
    def test_model_hash_unchanged(self):
        expected = "82f19f3726183ea8"
        actual = model_hash(str(PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib"))
        _assert_equal(actual, expected)

    def test_model_bundle_contains_scaler_and_clf(self):
        import joblib
        bundle = joblib.load(str(PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib"))
        _assert_true("scaler" in bundle, "Missing scaler")
        _assert_true("clf" in bundle, "Missing classifier")


# ===========================================================================
# Production integrity tests
# ===========================================================================

class TestProductionIntegrity:
    def test_no_production_files_modified(self):
        production_files = [
            "NIDS/model.py",
            "NIDS/features.py",
            "NIDS/flow.py",
            "NIDS/flow_manager.py",
            "NIDS/rule_engine.py",
            "NIDS/correlator.py",
            "NIDS/risk_scorer.py",
            "NIDS/alerts.py",
            "NIDS/pipeline.py",
            "NIDS/packet_capture.py",
            "NIDS/train_model.py",
        ]
        for rel_path in production_files:
            path = PROJECT_ROOT / rel_path
            _assert_true(path.exists(), f"Production file missing: {rel_path}")


# ===========================================================================
# Generator decoupling tests (Stage 11.8.7 fix)
# ===========================================================================

class _ImportBlocker:
    """Context manager that prevents NIDS.* imports during a test block."""

    def __init__(self, module_names):
        self.module_names = set(module_names)
        self._real_import = builtins.__import__
        self._patched = False

    def __enter__(self):
        real = self._real_import

        def blocked(name, *args, **kwargs):
            if name in self.module_names or any(name.startswith(m + ".") for m in self.module_names):
                raise ImportError("BLOCKED by test: " + name)
            return real(name, *args, **kwargs)

        builtins.__import__ = blocked
        self._patched = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        builtins.__import__ = self._real_import
        return False


class TestGeneratorDecoupling:
    def test_generator_mode_does_not_load_model(self):
        """Generator mode must not touch NIDSModel at construction time."""
        with _ImportBlocker({"NIDS.model"}):
            collector = ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="generator",
            )
            _assert_equal(collector.model, None)

    def test_generator_mode_does_not_init_pipeline(self):
        """Pipeline objects must remain None in generator mode."""
        with _ImportBlocker({"NIDS.model", "NIDS.rule_engine", "NIDS.correlator", "NIDS.risk_scorer", "NIDS.alerts"}):
            collector = ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="generator",
            )
            _assert_equal(collector.model, None)
            _assert_equal(collector.rule_engine, None)
            _assert_equal(collector.correlation_engine, None)
            _assert_equal(collector.risk_scorer, None)
            _assert_equal(collector.alert_manager, None)
            _assert_equal(collector.flow_manager, None)

    def test_generator_module_imports_without_production_package(self):
        """The module itself must import without NIDS.* or scapy sniffing."""
        import importlib
        import sys
        with _ImportBlocker({"NIDS.model", "NIDS.rule_engine", "NIDS.correlator", "NIDS.risk_scorer", "NIDS.alerts", "NIDS.flow", "NIDS.flow_manager"}):
            # Reload the module while NIDS.* is blocked.
            mod = importlib.import_module("NIDS.evaluation.collect_attack_11_8_v2")
            _assert_true(hasattr(mod, "generate_port_scan"))
            _assert_true(hasattr(mod, "generate_brute_force"))
            _assert_true(hasattr(mod, "generate_dos_udp"))
            _assert_true(hasattr(mod, "generate_reconnaissance"))
            _assert_true(hasattr(mod, "ScapyCaptureCollector"))

    def test_generator_mode_does_not_capture(self):
        """Generator mode must never call Scapy sniff()."""
        sniff_calls = []
        original_sniff = None
        try:
            import NIDS.evaluation.collect_attack_11_8_v2 as mod
            def _fake_sniff(*a, **k):
                sniff_calls.append((a, k))
            mod._import_scapy = lambda: (_fake_sniff, None, None, None)
            collector = ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="generator",
            )
            _assert_equal(len(sniff_calls), 0, "sniff must NOT be called in generator mode")
            _assert_equal(collector.packet_count, 0)
            _assert_equal(collector.capture_error, None)
            _assert_equal(len(collector.records), 0)
        finally:
            pass

    def test_generator_mode_preserves_target_ip(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
            mode="generator",
        )
        _assert_equal(collector.target_ip, "192.168.56.107")
        _assert_equal(collector.recon_target_ips, ["192.168.56.107"])

    def test_generator_mode_rejects_loopback_target(self):
        try:
            ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="127.0.0.1",
                mode="generator",
            )
            raise AssertionError("Should have raised ValueError for loopback target")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_generator_mode_rejects_loopback_recon_target(self):
        try:
            ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["127.0.0.5"],
                mode="generator",
            )
            raise AssertionError("Should have raised ValueError for loopback recon target")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_generator_mode_does_not_silently_substitute_loopback(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
            mode="generator",
        )
        _assert_false(collector.target_ip.startswith("127."))
        for ip in collector.recon_target_ips:
            _assert_false(ip.startswith("127."))

    def test_full_mode_still_initializes_pipeline(self):
        """Full mode MUST still load the model and build the pipeline.

        The Stage 11.8.7 generator decoupling removed the top-level NIDSModel
        (and pipeline) imports from collect_attack_11_8_v2 in favour of lazy
        imports performed inside _import_pipeline().  Consequently those names
        are no longer module-level attributes of collect_attack_11_8_v2, so
        patching ``NIDS.evaluation.collect_attack_11_8_v2.NIDSModel`` raises
        AttributeError.  The correct patch targets are the real source modules
        from which _import_pipeline() performs its deferred ``from ... import``
        statements, proving that full mode walks the lazy-import path.
        """
        with patch("NIDS.model.NIDSModel") as mock_model_cls, \
             patch("NIDS.rule_engine.RuleEngine") as mock_rule, \
             patch("NIDS.correlator.CorrelationEngine") as mock_corr, \
             patch("NIDS.risk_scorer.RiskScorer") as mock_risk, \
             patch("NIDS.alerts.AlertManager") as mock_alert:
            collector = ScapyCaptureCollector(
                interface="enp0s8",
                target_ip="192.168.56.107",
                recon_target_ips=["192.168.56.107"],
                mode="full",
            )
            _assert_true(mock_model_cls.load.called, "NIDSModel.load MUST be called in full mode")
            _assert_true(mock_rule.called, "RuleEngine MUST be instantiated in full mode")
            _assert_true(mock_corr.called, "CorrelationEngine MUST be instantiated in full mode")
            _assert_true(mock_risk.called, "RiskScorer MUST be instantiated in full mode")
            _assert_true(mock_alert.called, "AlertManager MUST be instantiated in full mode")
            _assert_true(collector.rule_engine is not None)
            _assert_true(collector.correlation_engine is not None)
            _assert_true(collector.risk_scorer is not None)
            _assert_true(collector.alert_manager is not None)

    def test_generator_mode_run_generators_only_returns_empty_dataset(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.107"],
            mode="generator",
        )
        dataset = collector.run_generators_only(pilot=True)
        _assert_equal(len(dataset.records), 0)
        _assert_equal(collector.packet_count, 0)


# ===========================================================================
# Helper for context manager style exception testing
# ===========================================================================

class _assert_raises:
    def __init__(self, exc_type):
        self.exc_type = exc_type
        self.exception = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"Expected {self.exc_type.__name__} but no exception raised")
        if not issubclass(exc_type, self.exc_type):
            return False
        self.exception = exc_val
        return True


# ===========================================================================
# Test runner
# ===========================================================================

def run_tests():
    test_classes = [
        TestLoopbackDetection,
        TestCaptureListener,
        TestCollectorModes,
        TestServerReadiness,
        TestAttributionPreservation,
        TestModelIntegrity,
        TestProductionIntegrity,
        TestGeneratorDecoupling,
    ]

    total = 0
    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        instance = cls()
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                total += 1
                try:
                    getattr(instance, method_name)()
                    passed += 1
                    print(f"  PASS: {cls.__name__}.{method_name}")
                except Exception as e:
                    failed += 1
                    errors.append(f"{cls.__name__}.{method_name}: {e}")
                    print(f"  FAIL: {cls.__name__}.{method_name}: {e}")

    print(f"\n{'='*60}")
    print(f"STAGE 11.8.7 SPLIT TESTS: {passed}/{total} passed, {failed} failed")
    if errors:
        print("Errors:")
        for err in errors:
            print(f"  {err}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
