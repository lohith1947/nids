"""
STAGE 11.3: Evaluation Harness Tests
======================================

Tests for the evaluation modules under NIDS/evaluation/.

Does NOT modify production code.

Run:
    python -m NIDS.tests.test_evaluation
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    ValidationIssue,
    ValidationVerdict,
)
from NIDS.evaluation.validation import (
    DatasetValidationResult,
    validate_dataset,
    validate_record,
    validate_session,
)
from NIDS.evaluation.splitting import (
    LeaveOneSessionOutSplitter,
    SessionKFoldSplitter,
    TemporalSplitter,
    split_dataset,
)

logging.basicConfig(level=logging.WARNING)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_record(
    session_id: str = "test-session",
    label: str = "BENIGN",
    features: List[float] = None,
    timestamp: float = 1000.0,
    traffic_category: str = "BENIGN",
) -> EvaluationRecord:
    if features is None:
        features = [0.0] * 18
    return EvaluationRecord(
        evaluation_session_id=session_id,
        collection_timestamp=timestamp,
        traffic_category=traffic_category,
        traffic_subtype="test",
        ground_truth_label=label,
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=6,
        features=features,
    )


def _make_session(
    session_id: str = "test-session",
    start: float = 1000.0,
    end: float = 1060.0,
) -> EvaluationSession:
    return EvaluationSession(
        session_id=session_id,
        start_timestamp=start,
        end_timestamp=end,
        traffic_category="BENIGN",
        traffic_subtype="test",
        interface="lo",
        source_machine="localhost",
        target_machine="localhost",
    )


def _assert_equal(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected}, got {actual}")


def _assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(f"{msg}: assertion failed")


# ===========================================================================
# Schema tests
# ===========================================================================

class TestEvaluationRecord:
    def test_valid_record(self):
        rec = _make_record()
        _assert_equal(rec.verdict(), ValidationVerdict.VALID, "Valid record should be VALID")

    def test_invalid_label(self):
        rec = _make_record(label="UNKNOWN_CLASS")
        _assert_equal(rec.verdict(), ValidationVerdict.INVALID, "Unknown label should be INVALID")

    def test_missing_features(self):
        rec = _make_record(features=[0.0] * 10)
        _assert_equal(rec.verdict(), ValidationVerdict.INVALID, "Wrong feature count should be INVALID")

    def test_missing_session_id(self):
        rec = _make_record()
        rec.evaluation_session_id = ""
        _assert_equal(rec.verdict(), ValidationVerdict.INVALID, "Empty session_id should be INVALID")

    def test_invalid_timestamp(self):
        rec = _make_record(timestamp=0.0)
        _assert_equal(rec.verdict(), ValidationVerdict.INVALID, "Zero timestamp should be INVALID")

    def test_serialization_roundtrip(self):
        rec = _make_record()
        rec.model_prediction = "DOS"
        rec.model_confidence = 0.85
        json_str = rec.to_json()
        rec2 = EvaluationRecord.from_json(json_str)
        _assert_equal(rec2.ground_truth_label, rec.ground_truth_label)
        _assert_equal(rec2.model_prediction, rec.model_prediction)
        _assert_equal(rec2.model_confidence, rec.model_confidence)

    def test_feature_range_warning(self):
        rec = _make_record(features=[1e12] * 18)
        _assert_equal(rec.verdict(), ValidationVerdict.WARNING, "Extreme features should be WARNING")


class TestEvaluationDataset:
    def test_add_record(self):
        ds = EvaluationDataset()
        rec = _make_record()
        ds.add_record(rec)
        _assert_equal(len(ds.records), 1, "Dataset should have 1 record")

    def test_label_distribution(self):
        ds = EvaluationDataset()
        ds.add_record(_make_record(label="BENIGN"))
        ds.add_record(_make_record(label="BENIGN"))
        ds.add_record(_make_record(label="DOS"))
        dist = ds.label_distribution()
        _assert_equal(dist["BENIGN"], 2)
        _assert_equal(dist["DOS"], 1)

    def test_validation_summary(self):
        ds = EvaluationDataset()
        ds.add_record(_make_record())
        ds.add_record(_make_record(label="INVALID"))
        summary = ds.validation_summary()
        _assert_equal(summary["VALID"], 1)
        _assert_equal(summary["INVALID"], 1)

    def test_jsonl_roundtrip(self):
        ds = EvaluationDataset(name="test")
        ds.add_record(_make_record(session_id="s1"))
        ds.add_record(_make_record(session_id="s2", label="DOS"))

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
            path = f.name

        try:
            ds.to_jsonl(path)
            ds2 = EvaluationDataset.from_jsonl(path)
            _assert_equal(len(ds2.records), 2)
            _assert_equal(ds2.label_distribution()["BENIGN"], 1)
            _assert_equal(ds2.label_distribution()["DOS"], 1)
        finally:
            Path(path).unlink()


# ===========================================================================
# Validation tests
# ===========================================================================

class TestValidation:
    def test_valid_dataset(self):
        ds = EvaluationDataset()
        for lbl in CLASS_LABELS:
            for _ in range(20):
                ds.add_record(_make_record(label=lbl))
        result = validate_dataset(ds)
        _assert_true(result.is_usable, "Dataset with all valid records should be usable")
        _assert_equal(result.invalid_count, 0)

    def test_missing_labels(self):
        ds = EvaluationDataset()
        for _ in range(20):
            ds.add_record(_make_record(label="BENIGN"))
        result = validate_dataset(ds)
        _assert_true(any("missing_labels" in i.code for i in result.issues), "Missing labels should be flagged")

    def test_duplicate_features(self):
        ds = EvaluationDataset()
        features = [42.0] * 18
        for _ in range(10):
            ds.add_record(_make_record(features=features))
        result = validate_dataset(ds)
        _assert_equal(result.duplicate_feature_count, 9, "Should have 9 duplicate feature vectors")

    def test_overlapping_sessions(self):
        ds = EvaluationDataset()
        ds.add_record(_make_record(session_id="s1"))
        ds.add_record(_make_record(session_id="s2"))
        ds.sessions["s1"] = _make_session("s1", start=1000.0, end=1060.0)
        ds.sessions["s2"] = _make_session("s2", start=1030.0, end=1090.0)
        result = validate_dataset(ds)
        _assert_true(len(result.overlapping_sessions) > 0, "Overlapping sessions should be flagged")

    def test_insufficient_samples(self):
        ds = EvaluationDataset()
        for _ in range(5):
            ds.add_record(_make_record(label="DOS"))
        result = validate_dataset(ds)
        _assert_true(any("insufficient_samples" in i.code for i in result.issues), "Low sample count should be warned")


# ===========================================================================
# Splitting tests
# ===========================================================================

class TestTemporalSplitter:
    def test_basic_split(self):
        ds = EvaluationDataset()
        for i in range(10):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid, timestamp=1000.0 + i * 60))
            ds.sessions[sid] = _make_session(sid, start=1000.0 + i * 60, end=1060.0 + i * 60)

        splitter = TemporalSplitter(train_fraction=0.7)
        result = splitter.split(ds)

        _assert_equal(len(result.train_sessions), 7, "Should have 7 train sessions")
        _assert_equal(len(result.test_sessions), 3, "Should have 3 test sessions")
        _assert_equal(result.train_count + result.test_count, 10, "Total records should match")
        _assert_true(set(result.train_sessions).isdisjoint(set(result.test_sessions)), "Train/test should be disjoint")

    def test_temporal_order_preserved(self):
        ds = EvaluationDataset()
        for i in range(5):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid, timestamp=1000.0 + i * 60))
            ds.sessions[sid] = _make_session(sid, start=1000.0 + i * 60, end=1060.0 + i * 60)

        splitter = TemporalSplitter(train_fraction=0.6)
        result = splitter.split(ds)

        last_train_end = max(ds.sessions[s].end_timestamp for s in result.train_sessions)
        first_test_start = min(ds.sessions[s].start_timestamp for s in result.test_sessions)
        _assert_true(last_train_end <= first_test_start, "Train sessions should end before test sessions start")


class TestSessionKFoldSplitter:
    def test_kfold_count(self):
        ds = EvaluationDataset()
        for i in range(10):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid))
            ds.sessions[sid] = _make_session(sid)

        splitter = SessionKFoldSplitter(n_splits=5)
        results = splitter.split(ds)
        _assert_equal(len(results), 5, "Should produce 5 folds")

    def test_no_session_leakage(self):
        ds = EvaluationDataset()
        for i in range(6):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid))
            ds.sessions[sid] = _make_session(sid)

        splitter = SessionKFoldSplitter(n_splits=3)
        results = splitter.split(ds)
        for result in results:
            _assert_true(set(result.train_sessions).isdisjoint(set(result.test_sessions)), "Sessions should not leak across folds")


class TestLeaveOneSessionOutSplitter:
    def test_loso_count(self):
        ds = EvaluationDataset()
        for i in range(4):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid))
            ds.sessions[sid] = _make_session(sid)

        splitter = LeaveOneSessionOutSplitter(min_session_samples=1)
        results = splitter.split(ds)
        _assert_equal(len(results), 4, "Should produce 4 LOSO folds")

    def test_loso_test_size(self):
        ds = EvaluationDataset()
        for i in range(4):
            sid = f"session-{i:02d}"
            ds.add_record(_make_record(session_id=sid))
            ds.sessions[sid] = _make_session(sid)

        splitter = LeaveOneSessionOutSplitter(min_session_samples=1)
        results = splitter.split(ds)
        for result in results:
            _assert_equal(len(result.test_sessions), 1, "Each LOSO fold should have 1 test session")
            _assert_equal(len(result.train_sessions), 3, "Each LOSO fold should have 3 train sessions")


# ===========================================================================
# Edge case tests
# ===========================================================================

class TestEdgeCases:
    def test_empty_dataset(self):
        ds = EvaluationDataset()
        result = validate_dataset(ds)
        _assert_equal(result.total_records, 0)
        _assert_true(not result.is_usable, "Empty dataset should not be usable")

    def test_insufficient_sessions_for_temporal_split(self):
        ds = EvaluationDataset()
        ds.add_record(_make_record(session_id="s1"))
        ds.sessions["s1"] = _make_session("s1")

        splitter = TemporalSplitter()
        try:
            splitter.split(ds)
            raise AssertionError("Should have raised ValueError for 1-session dataset")
        except ValueError:
            pass  # Expected


# ===========================================================================
# Test runner
# ===========================================================================

def run_tests():
    test_classes = [
        TestEvaluationRecord,
        TestEvaluationDataset,
        TestValidation,
        TestTemporalSplitter,
        TestSessionKFoldSplitter,
        TestLeaveOneSessionOutSplitter,
        TestEdgeCases,
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
    print(f"EVALUATION TESTS: {passed}/{total} passed, {failed} failed")
    if errors:
        print("Errors:")
        for err in errors:
            print(f"  {err}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
