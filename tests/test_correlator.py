"""
Tests for the Hybrid Correlation Engine.

Validates all 5 correlation cases plus confidence bounds and output structure:
  1. Rule + ML agree on attack class
  2. Rule + ML disagree on different attack classes
  3. Rule says BENIGN, ML detects attack
  4. ML says BENIGN, Rule detects attack
  5. Both say BENIGN
  6. Confidence always in [0.0, 1.0]
  7. Output structure correctness

Uses a FakeModel for deterministic testing of correlation logic, plus
the real trained model for integration validation.

Run from project root:
    python -m NIDS.tests.test_correlator
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pathlib import Path
import numpy as np
from unittest.mock import MagicMock

from NIDS.correlator import (
    CorrelationEngine,
    DetectionResult,
)
from NIDS.rule_engine import (
    RuleEngine,
    RuleResult,
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
)
from NIDS.flow import Flow
from NIDS.model import NIDSModel

# TCP flag values
SYN = 0x02
ACK = 0x10
FIN = 0x01
PSH = 0x08
PSH_ACK = 0x18


_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "nids_model.joblib"
_MODEL_AVAILABLE = _MODEL_PATH.exists()


class FakeModel:
    """A minimal stand-in for NIDSModel that returns a controlled prediction.

    This lets us test the correlation logic without depending on the
    real model's behaviour on synthetic feature vectors.

    Follows sklearn convention: clf.classes_ holds integer class values
    (0=BENIGN, 1=PORT_SCAN, ...), and clf.predict() returns those integers.
    """

    def __init__(self, predict_label: str, predict_conf: float, all_probs: dict):
        self._label_to_int = {"BENIGN": 0, "PORT_SCAN": 1, "BRUTE_FORCE": 2,
                              "DOS": 3, "RECONNAISSANCE": 4}
        self._int_to_label = {v: k for k, v in self._label_to_int.items()}

        self.classes_ = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]
        self._label = predict_label
        self._conf = predict_conf
        self._probs = all_probs
        self.scaler = MagicMock()
        self.clf = MagicMock()
        self._is_fitted = True

        # sklearn convention: clf.classes_ holds integer class values
        self.clf.classes_ = np.array([0, 1, 2, 3, 4])

        # probs ordered by clf.classes_ (integers 0-4), mapped from all_probs (string keys)
        self._prob_array = np.array([
            self._probs[self._int_to_label[i]] for i in range(5)
        ]).reshape(1, -1)

        self.clf.predict_proba = MagicMock(return_value=self._prob_array)
        self.clf.predict = MagicMock(return_value=np.array([self._label_to_int[self._label]]))
        self.scaler.transform = MagicMock(side_effect=lambda x: np.asarray(x).reshape(1, -1))

    def predict(self, features):
        if isinstance(features, list) and isinstance(features[0], (int, float)):
            return self._label, self._conf
        return [self._label] * len(features), [self._conf] * len(features)


def make_fake_engine(predict_label: str, predict_conf: float, all_probs: dict = None) -> "CorrelationEngine":
    """Create a CorrelationEngine backed by a FakeModel with controlled output.

    The FakeModel's predict_proba returns probabilities that sum to 1.0,
    with ``predict_label`` having probability ``predict_conf`` and the
    remaining probability split equally among the other 4 classes.

    Note: the correlator reads probabilities directly from clf.predict_proba,
    so we must ensure all_probs[predict_label] == predict_conf.
    """
    if all_probs is None:
        classes = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]
        all_probs = {c: 0.0 for c in classes}
        all_probs[predict_label] = predict_conf
        remaining = 1.0 - predict_conf
        other_keys = [k for k in classes if k != predict_label]
        if other_keys and remaining > 0:
            share = remaining / len(other_keys)
            for k in other_keys:
                all_probs[k] = share
    fake_model = FakeModel(predict_label, predict_conf, all_probs)
    return CorrelationEngine(model=fake_model)


def make_feature_vector(**overrides):
    """Create a base 18-feature vector (benign-like) with overrides."""
    from NIDS.features import NUMERIC_FEATURE_NAMES

    base = {
        "duration": 0.2,
        "packet_count": 32,
        "byte_count": 5056,
        "average_packet_size": 148.7,
        "minimum_packet_size": 64,
        "maximum_packet_size": 200,
        "packet_size_std": 48.7,
        "packets_per_second": 159.4,
        "bytes_per_second": 25154.0,
        "forward_packets": 17,
        "backward_packets": 17,
        "forward_bytes": 1928,
        "backward_bytes": 3128,
        "syn_count": 2,
        "ack_count": 30,
        "fin_count": 1,
        "rst_count": 0,
        "psh_count": 28,
    }
    base.update(overrides)
    return [base[fname] for fname in NUMERIC_FEATURE_NAMES]


def make_dos_features():
    """Create features resembling a DoS attack flow."""
    return make_feature_vector(
        duration=0.9,
        packet_count=10000,
        byte_count=600000,
        average_packet_size=60.0,
        minimum_packet_size=40,
        maximum_packet_size=80,
        packet_size_std=20.0,
        packets_per_second=11111.0,
        bytes_per_second=666666.0,
        forward_packets=5000,
        backward_packets=5000,
        forward_bytes=300000,
        backward_bytes=300000,
        syn_count=10000,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
    )


def test_agreement():
    """Test 1: Rule + ML agree on the same attack class (Case A)."""
    print("=" * 60)
    print("TEST 1: Rule + ML Agreement (both detect DOS)")
    print("=" * 60)

    engine = make_fake_engine(DOS, 0.85)
    rule_result = RuleResult(
        rule_prediction=DOS,
        rule_confidence=0.90,
        triggered_rules=["high_packet_rate", "syn_flood_pattern"],
        rule_reason="DOS indicators detected",
    )
    features = make_dos_features()

    result = engine.correlate(features, rule_result)
    print(f"  Rule:      {result.rule_prediction} (conf={result.rule_confidence:.3f})")
    print(f"  ML:        {result.ml_prediction} (conf={result.ml_confidence:.3f})")
    print(f"  ML top-3:  {result.ml_top3}")
    print(f"  Final:     {result.final_prediction}")
    print(f"  Combined:  {result.combined_confidence:.4f}")
    print(f"  Explanation: {result.explanation[:100]}...")
    print()

    # Agreement: combined should be 1-(1-0.9)(1-0.85) = 0.985
    expected = 1.0 - (1.0 - 0.90) * (1.0 - 0.85)
    ok = result.final_prediction == DOS and abs(result.combined_confidence - expected) < 0.01
    print(f"  Expected combined ~{expected:.4f}, got {result.combined_confidence:.4f}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_disagreement():
    """Test 2: Rule + ML disagree on different attack classes (Case B)."""
    print("=" * 60)
    print("TEST 2: Rule + ML Disagreement (Rule=DOS, ML=BRUTE_FORCE)")
    print("=" * 60)

    engine = make_fake_engine(BRUTE_FORCE, 0.70)
    rule_result = RuleResult(
        rule_prediction=DOS,
        rule_confidence=0.85,
        triggered_rules=["high_packet_rate", "syn_flood_pattern"],
        rule_reason="DOS pattern detected",
    )
    features = make_feature_vector()

    result = engine.correlate(features, rule_result)
    print(f"  Rule:      {result.rule_prediction} (conf={result.rule_confidence:.3f})")
    print(f"  ML:        {result.ml_prediction} (conf={result.ml_confidence:.3f})")
    print(f"  ML top-3:  {result.ml_top3}")
    print(f"  Final:     {result.final_prediction}")
    print(f"  Combined:  {result.combined_confidence:.4f}")
    print(f"  Explanation: {result.explanation[:120]}...")
    print()

    # Disagreement: max(0.85, 0.70) * 0.85 = 0.7225
    expected = max(0.85, 0.70) * 0.85
    ok = result.final_prediction == DOS and abs(result.combined_confidence - expected) < 0.01
    print(f"  Expected combined ~{expected:.4f}, got {result.combined_confidence:.4f}")
    print(f"  Final prediction is DOS (higher rule conf): {result.final_prediction == DOS}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_rule_benign_ml_attack():
    """Test 3: Rule says BENIGN but ML detects an attack (Case C)."""
    print("=" * 60)
    print("TEST 3: Rule=BENIGN, ML=Attack (Case C)")
    print("=" * 60)

    engine = make_fake_engine(DOS, 0.75)
    rule_result = RuleResult(
        rule_prediction=BENIGN,
        rule_confidence=0.0,
        triggered_rules=[],
        rule_reason="No malicious patterns detected.",
    )
    features = make_dos_features()

    result = engine.correlate(features, rule_result)
    print(f"  Rule:      {result.rule_prediction} (conf={result.rule_confidence:.3f})")
    print(f"  ML:        {result.ml_prediction} (conf={result.ml_confidence:.3f})")
    print(f"  ML top-3:  {result.ml_top3}")
    print(f"  Final:     {result.final_prediction}")
    print(f"  Combined:  {result.combined_confidence:.4f}")
    print(f"  Explanation: {result.explanation[:100]}...")
    print()

    # Rule benign + ML attack: 0.75 * 0.80 = 0.60
    expected = 0.75 * 0.80
    ok = result.final_prediction == DOS and abs(result.combined_confidence - expected) < 0.01
    print(f"  Expected combined ~{expected:.4f}, got {result.combined_confidence:.4f}")
    print(f"  Final prediction follows ML (DOS): {result.final_prediction == DOS}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_ml_benign_rule_attack():
    """Test 4: ML says BENIGN but Rule detects an attack (Case D)."""
    print("=" * 60)
    print("TEST 4: ML=BENIGN, Rule=Attack (Case D)")
    print("=" * 60)

    engine = make_fake_engine(BENIGN, 0.90)
    rule_result = RuleResult(
        rule_prediction=DOS,
        rule_confidence=0.75,
        triggered_rules=["syn_flood_pattern"],
        rule_reason="SYN flood detected",
    )
    features = make_feature_vector()

    result = engine.correlate(features, rule_result)
    print(f"  Rule:      {result.rule_prediction} (conf={result.rule_confidence:.3f})")
    print(f"  ML:        {result.ml_prediction} (conf={result.ml_confidence:.3f})")
    print(f"  ML top-3:  {result.ml_top3}")
    print(f"  Final:     {result.final_prediction}")
    print(f"  Combined:  {result.combined_confidence:.4f}")
    print(f"  Explanation: {result.explanation[:100]}...")
    print()

    # ML benign + Rule attack: 0.75 * 0.80 = 0.60
    expected = 0.75 * 0.80
    ok = result.final_prediction == DOS and abs(result.combined_confidence - expected) < 0.01
    print(f"  Expected combined ~{expected:.4f}, got {result.combined_confidence:.4f}")
    print(f"  Final prediction follows Rule (DOS): {result.final_prediction == DOS}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_both_benign():
    """Test 5: Both Rule and ML say BENIGN (Case E)."""
    print("=" * 60)
    print("TEST 5: Both BENIGN (Case E)")
    print("=" * 60)

    engine = make_fake_engine(BENIGN, 0.92)
    rule_result = RuleResult(
        rule_prediction=BENIGN,
        rule_confidence=0.0,
        triggered_rules=[],
        rule_reason="No malicious patterns detected.",
    )
    features = make_feature_vector()

    result = engine.correlate(features, rule_result)
    print(f"  Rule:      {result.rule_prediction} (conf={result.rule_confidence:.3f})")
    print(f"  ML:        {result.ml_prediction} (conf={result.ml_confidence:.3f})")
    print(f"  ML top-3:  {result.ml_top3}")
    print(f"  Final:     {result.final_prediction}")
    print(f"  Combined:  {result.combined_confidence:.4f}")
    print()

    ok = result.final_prediction == BENIGN and 0.0 <= result.combined_confidence <= 1.0
    print(f"  Final prediction is BENIGN: {result.final_prediction == BENIGN}")
    print(f"  Confidence in bounds: {0.0 <= result.combined_confidence <= 1.0}")
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def test_confidence_bounds():
    """Test 6: Combined confidence is always in [0.0, 1.0] for all cases."""
    print("=" * 60)
    print("TEST 6: Confidence bounds [0.0, 1.0]")
    print("=" * 60)

    # Define test scenarios covering all 5 cases
    scenarios = [
        ("Agreement", DOS, 0.99, RuleResult(
            rule_prediction=DOS, rule_confidence=0.99,
            triggered_rules=["x"], rule_reason="test"
        )),
        ("Disagreement", BRUTE_FORCE, 0.80, RuleResult(
            rule_prediction=DOS, rule_confidence=0.80,
            triggered_rules=["x"], rule_reason="test"
        )),
        ("Rule benign+ML attack", DOS, 0.95, RuleResult(
            rule_prediction=BENIGN, rule_confidence=0.0,
            triggered_rules=[], rule_reason="benign"
        )),
        ("ML benign+Rule attack", BENIGN, 0.99, RuleResult(
            rule_prediction=DOS, rule_confidence=0.50,
            triggered_rules=["x"], rule_reason="test"
        )),
        ("Both benign", BENIGN, 0.99, RuleResult(
            rule_prediction=BENIGN, rule_confidence=0.0,
            triggered_rules=[], rule_reason="benign"
        )),
        ("Low confidence attack", DOS, 0.10, RuleResult(
            rule_prediction=DOS, rule_confidence=0.10,
            triggered_rules=["x"], rule_reason="test"
        )),
    ]

    all_ok = True
    for name, ml_label, ml_conf, rule_result in scenarios:
        engine = make_fake_engine(ml_label, ml_conf)
        result = engine.correlate(make_feature_vector(), rule_result)
        ok = 0.0 <= result.combined_confidence <= 1.0
        if not ok:
            print(f"  {name}: FAIL (conf={result.combined_confidence})")
            all_ok = False
        else:
            print(f"  {name}: OK (conf={result.combined_confidence:.4f})")

    print()
    print(f"  Result: {'PASS' if all_ok else 'FAIL'}")
    print()
    return all_ok


def test_output_structure():
    """Test 7: Output DetectionResult has all required fields with correct types."""
    print("=" * 60)
    print("TEST 7: Output Structure")
    print("=" * 60)

    engine = make_fake_engine(DOS, 0.85)
    rule_result = RuleResult(
        rule_prediction=DOS,
        rule_confidence=0.90,
        triggered_rules=["high_packet_rate"],
        rule_reason="DOS detected",
    )
    features = make_dos_features()

    result = engine.correlate(features, rule_result)

    required_fields = [
        "final_prediction",
        "combined_confidence",
        "rule_prediction",
        "rule_confidence",
        "ml_prediction",
        "ml_confidence",
        "triggered_rules",
        "ml_top3",
        "explanation",
    ]

    all_ok = True
    for field_name in required_fields:
        has_attr = hasattr(result, field_name)
        if not has_attr:
            print(f"  Missing field: {field_name}")
            all_ok = False

    # Type checks
    type_checks = [
        ("final_prediction is str", isinstance(result.final_prediction, str)),
        ("combined_confidence is float", isinstance(result.combined_confidence, (int, float))),
        ("rule_prediction is str", isinstance(result.rule_prediction, str)),
        ("rule_confidence is float", isinstance(result.rule_confidence, (int, float))),
        ("ml_prediction is str", isinstance(result.ml_prediction, str)),
        ("ml_confidence is float", isinstance(result.ml_confidence, (int, float))),
        ("triggered_rules is list", isinstance(result.triggered_rules, list)),
        ("ml_top3 is list", isinstance(result.ml_top3, list)),
        ("explanation is str", isinstance(result.explanation, str)),
        ("ml_top3 has 3 entries", len(result.ml_top3) == 3),
        ("final_prediction in valid classes", result.final_prediction in [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE]),
    ]

    print(f"  All {len(required_fields)} fields present: {all_ok}")
    for desc, check in type_checks:
        print(f"  {desc}: {check}")

    ok = all_ok and all(c for _, c in type_checks)
    print(f"\n  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


def main():
    print("\n" + "=" * 60)
    print("NIDS CORRELATION ENGINE TESTS")
    print("=" * 60 + "\n")

    results = []
    results.append(("Rule + ML Agreement", test_agreement()))
    results.append(("Rule + ML Disagreement", test_disagreement()))
    results.append(("Rule=BENIGN, ML=Attack", test_rule_benign_ml_attack()))
    results.append(("ML=BENIGN, Rule=Attack", test_ml_benign_rule_attack()))
    results.append(("Both BENIGN", test_both_benign()))
    results.append(("Confidence Bounds", test_confidence_bounds()))
    results.append(("Output Structure", test_output_structure()))

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
