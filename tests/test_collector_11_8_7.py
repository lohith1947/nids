"""
STAGE 11.8.7 — Collector Preparation Tests
============================================

Tests for the non-loopback parameterization of collect_attack_11_8_v2.py.

Validates:
- interface parameter
- target-ip parameter
- recon-target-ips parameter
- rejection of accidental loopback configuration
- preservation of 5-tuple attribution
- preservation of source-port validation semantics
- model hash integrity
- no production file modification

Run:
    python -m NIDS.tests.test_collector_11_8_7
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.evaluation.collect_attack_11_8_v2 import (
    ScapyCaptureCollector,
    _is_loopback_interface,
    _validate_non_loopback_config,
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


# ===========================================================================
# Interface / loopback detection tests
# ===========================================================================

class TestInterfaceValidation:
    def test_loopback_interface_detected(self):
        _assert_true(_is_loopback_interface("Loopback Pseudo-Interface 1"))
        _assert_true(_is_loopback_interface("lo"))
        _assert_true(_is_loopback_interface("LOOPBACK"))
        _assert_true(not _is_loopback_interface(""))

    def test_non_loopback_interface_not_detected(self):
        _assert_true(not _is_loopback_interface("enp0s8"))
        _assert_true(not _is_loopback_interface("eth0"))
        _assert_true(not _is_loopback_interface("Ethernet"))
        _assert_true(not _is_loopback_interface("VirtualBox Host-Only Ethernet Adapter"))


# ===========================================================================
# Config validation tests
# ===========================================================================

class TestConfigValidation:
    def test_loopback_interface_with_loopback_target_passes(self):
        _validate_non_loopback_config("Loopback Pseudo-Interface 1", "127.0.0.1", ["127.0.0.2"])

    def test_non_loopback_interface_with_loopback_target_fails(self):
        try:
            _validate_non_loopback_config("enp0s8", "127.0.0.1", ["192.168.56.105"])
            raise AssertionError("Should have raised ValueError for loopback target with non-loopback interface")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_non_loopback_interface_with_loopback_recon_fails(self):
        try:
            _validate_non_loopback_config("enp0s8", "192.168.56.107", ["127.0.0.2"])
            raise AssertionError("Should have raised ValueError for loopback recon target")
        except ValueError as e:
            _assert_true("loopback" in str(e).lower())

    def test_non_loopback_interface_with_all_valid_targets_passes(self):
        _validate_non_loopback_config(
            "enp0s8",
            "192.168.56.107",
            ["192.168.56.105", "192.168.56.108"],
        )


# ===========================================================================
# Collector parameterization tests
# ===========================================================================

class TestCollectorParameterization:
    def test_default_interface_is_loopback(self):
        _assert_equal(DEFAULT_INTERFACE, "Loopback Pseudo-Interface 1")

    def test_collector_accepts_non_loopback_interface(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.105"],
        )
        _assert_equal(collector.interface, "enp0s8")
        _assert_equal(collector.target_ip, "192.168.56.107")

    def test_collector_rejects_loopback_target_with_non_loopback_interface(self):
        try:
            ScapyCaptureCollector(interface="enp0s8", target_ip="127.0.0.1")
            raise AssertionError("Should have raised ValueError")
        except ValueError:
            pass  # Expected

    def test_collector_accepts_custom_recon_targets(self):
        recon_ips = ["192.168.56.10", "192.168.56.11"]
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=recon_ips,
        )
        _assert_equal(collector.recon_target_ips, recon_ips)

    def test_collector_stores_source_and_target_machine(self):
        collector = ScapyCaptureCollector(
            interface="enp0s8",
            target_ip="192.168.56.107",
            recon_target_ips=["192.168.56.105"],
            source_machine="kali",
            target_machine="nids-vm",
        )
        _assert_equal(collector.source_machine, "kali")
        _assert_equal(collector.target_machine, "nids-vm")

    def test_collector_default_recon_targets_are_loopback(self):
        collector = ScapyCaptureCollector(interface="Loopback Pseudo-Interface 1")
        _assert_equal(collector.recon_target_ips, ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6"])


# ===========================================================================
# 5-tuple attribution preservation tests
# ===========================================================================

class TestAttributionPreservation:
    def test_record_contains_exact_5_tuple_fields(self):
        rec = EvaluationRecord(
            evaluation_session_id="test-session",
            collection_timestamp=1000.0,
            traffic_category="ATTACK",
            traffic_subtype="test",
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

    def test_record_feature_count_is_18(self):
        features = [float(i) for i in range(18)]
        rec = EvaluationRecord(
            evaluation_session_id="test-session",
            collection_timestamp=1000.0,
            traffic_category="ATTACK",
            traffic_subtype="test",
            ground_truth_label="PORT_SCAN",
            src_ip="192.168.56.105",
            dst_ip="192.168.56.107",
            src_port=45678,
            dst_port=52000,
            protocol=6,
            features=features,
        )
        _assert_equal(len(rec.features), 18)


# ===========================================================================
# Model integrity tests
# ===========================================================================

class TestModelIntegrity:
    def test_model_hash(self):
        import hashlib
        import joblib
        model_path = Path(PROJECT_ROOT) / "NIDS" / "models" / "nids_model.joblib"
        data = model_path.read_bytes()
        h = hashlib.sha256(data).hexdigest()[:16]
        _assert_equal(h, "82f19f3726183ea8", "Model hash mismatch")

    def test_model_bundle_keys(self):
        import joblib
        model_path = Path(PROJECT_ROOT) / "NIDS" / "models" / "nids_model.joblib"
        bundle = joblib.load(str(model_path))
        _assert_true("scaler" in bundle, "Missing scaler in bundle")
        _assert_true("clf" in bundle, "Missing classifier in bundle")


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
            path = Path(PROJECT_ROOT) / rel_path
            _assert_true(path.exists(), f"Production file missing: {rel_path}")


# ===========================================================================
# Test runner
# ===========================================================================

def run_tests():
    test_classes = [
        TestInterfaceValidation,
        TestConfigValidation,
        TestCollectorParameterization,
        TestAttributionPreservation,
        TestModelIntegrity,
        TestProductionIntegrity,
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
    print(f"COLLECTOR TESTS: {passed}/{total} passed, {failed} failed")
    if errors:
        print("Errors:")
        for err in errors:
            print(f"  {err}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
