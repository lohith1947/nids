"""
Tests for the Risk Scorer (Stage 4).

Validates:
  1.  BENIGN at low confidence → very low risk
  2.  BENIGN at high confidence → still very low risk
  3.  PORT_SCAN low confidence
  4.  PORT_SCAN high confidence
  5.  BRUTE_FORCE low confidence
  6.  BRUTE_FORCE high confidence
  7.  DOS low confidence
  8.  DOS high confidence
  9.  RECONNAISSANCE low confidence
  10. RECONNAISSANCE high confidence
  11. Score boundaries [0, 100]
  12. Monotonicity: higher confidence → higher risk (same class)
  13. Invalid confidence handling (negative, >1)
  14. Unknown prediction handling
  15. RiskResult structure (all fields present and typed correctly)

Run from project root:
    python -m NIDS.tests.test_risk_scorer
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dataclasses import is_dataclass
from NIDS.risk_scorer import RiskScorer, RiskResult, RISK_CONFIG
from NIDS.correlator import DetectionResult
from NIDS.rule_engine import (
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
)


def make_detection(prediction, confidence, explanation="test", triggered_rules=None, ml_top3=None):
    """Create a DetectionResult for testing."""
    return DetectionResult(
        final_prediction=prediction,
        combined_confidence=confidence,
        rule_prediction=prediction,
        rule_confidence=confidence,
        ml_prediction=prediction,
        ml_confidence=confidence,
        triggered_rules=triggered_rules or [],
        ml_top3=ml_top3 or [],
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# Helper to run a single test and print results
# ---------------------------------------------------------------------------

def _run_test(name, func):
    print("=" * 60)
    print(f"TEST: {name}")
    print("=" * 60)
    try:
        result = func()
        ok = result
    except Exception as e:
        print(f"  EXCEPTION: {e}")
        ok = False
    print(f"  Result: {'PASS' if ok else 'FAIL'}")
    print()
    return ok


# ---------------------------------------------------------------------------
# Individual tests
# ---------------------------------------------------------------------------

def test_benign_low_confidence():
    scorer = RiskScorer()
    d = make_detection(BENIGN, 0.10)
    r = scorer.score(d)

    base = RISK_CONFIG[BENIGN]["base"]
    ceiling = RISK_CONFIG[BENIGN]["ceiling"]
    expected = round(base + (ceiling - base) * 0.10, 1)

    print(f"  Prediction: {r.prediction}")
    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Confidence: {r.confidence}")
    print(f"  Severity:   {r.severity}")
    print(f"  Explanation: {r.explanation[:100]}...")

    ok = (
        r.risk_score == expected
        and r.risk_score <= 5.0
        and r.prediction == BENIGN
        and r.severity == "INFORMATIONAL"
    )
    return ok


def test_benign_high_confidence():
    scorer = RiskScorer()
    d = make_detection(BENIGN, 0.99)
    r = scorer.score(d)

    base = RISK_CONFIG[BENIGN]["base"]
    ceiling = RISK_CONFIG[BENIGN]["ceiling"]
    expected = round(base + (ceiling - base) * 0.99, 1)

    print(f"  Prediction: {r.prediction}")
    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Confidence: {r.confidence}")
    print(f"  Severity:   {r.severity}")

    ok = (
        r.risk_score == expected
        and r.risk_score <= 5.0
        and r.prediction == BENIGN
    )
    return ok


def test_port_scan_low():
    scorer = RiskScorer()
    d = make_detection(PORT_SCAN, 0.30)
    r = scorer.score(d)

    base = RISK_CONFIG[PORT_SCAN]["base"]
    ceiling = RISK_CONFIG[PORT_SCAN]["ceiling"]
    expected = round(base + (ceiling - base) * 0.30, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Severity:   {r.severity}")

    ok = r.risk_score == expected and r.severity == "MEDIUM"
    return ok


def test_port_scan_high():
    scorer = RiskScorer()
    d = make_detection(PORT_SCAN, 0.90)
    r = scorer.score(d)

    base = RISK_CONFIG[PORT_SCAN]["base"]
    ceiling = RISK_CONFIG[PORT_SCAN]["ceiling"]
    expected = round(base + (ceiling - base) * 0.90, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")

    ok = r.risk_score == expected and r.risk_score < 40.0  # still below BRUTE_FORCE base
    return ok


def test_brute_force_low():
    scorer = RiskScorer()
    d = make_detection(BRUTE_FORCE, 0.20)
    r = scorer.score(d)

    base = RISK_CONFIG[BRUTE_FORCE]["base"]
    ceiling = RISK_CONFIG[BRUTE_FORCE]["ceiling"]
    expected = round(base + (ceiling - base) * 0.20, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Severity:   {r.severity}")

    ok = r.risk_score == expected and r.severity == "HIGH"
    return ok


def test_brute_force_high():
    scorer = RiskScorer()
    d = make_detection(BRUTE_FORCE, 0.95)
    r = scorer.score(d)

    base = RISK_CONFIG[BRUTE_FORCE]["base"]
    ceiling = RISK_CONFIG[BRUTE_FORCE]["ceiling"]
    expected = round(base + (ceiling - base) * 0.95, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")

    ok = r.risk_score == expected and r.risk_score <= 100.0
    return ok


def test_dos_low():
    scorer = RiskScorer()
    d = make_detection(DOS, 0.50)
    r = scorer.score(d)

    base = RISK_CONFIG[DOS]["base"]
    ceiling = RISK_CONFIG[DOS]["ceiling"]
    expected = round(base + (ceiling - base) * 0.50, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Severity:   {r.severity}")

    ok = r.risk_score == expected and r.severity == "CRITICAL"
    return ok


def test_dos_high():
    scorer = RiskScorer()
    d = make_detection(DOS, 1.0)
    r = scorer.score(d)

    base = RISK_CONFIG[DOS]["base"]
    ceiling = RISK_CONFIG[DOS]["ceiling"]
    expected = round(base + (ceiling - base) * 1.0, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")

    ok = r.risk_score == expected
    return ok


def test_reconnaissance_low():
    scorer = RiskScorer()
    d = make_detection(RECONNAISSANCE, 0.25)
    r = scorer.score(d)

    base = RISK_CONFIG[RECONNAISSANCE]["base"]
    ceiling = RISK_CONFIG[RECONNAISSANCE]["ceiling"]
    expected = round(base + (ceiling - base) * 0.25, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    print(f"  Severity:   {r.severity}")

    ok = r.risk_score == expected and r.severity == "MEDIUM"
    return ok


def test_reconnaissance_high():
    scorer = RiskScorer()
    d = make_detection(RECONNAISSANCE, 0.95)
    r = scorer.score(d)

    base = RISK_CONFIG[RECONNAISSANCE]["base"]
    ceiling = RISK_CONFIG[RECONNAISSANCE]["ceiling"]
    expected = round(base + (ceiling - base) * 0.95, 1)

    print(f"  Risk score: {r.risk_score} (expected ~{expected})")
    return r.risk_score == expected


def test_score_boundaries():
    """Score is always in [0, 100] for all classes at conf 0 and 1."""
    scorer = RiskScorer()
    classes = [BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE]

    all_ok = True
    for cls in classes:
        for conf in [0.0, 1.0, 0.5, 0.123, 0.999]:
            d = make_detection(cls, conf)
            r = scorer.score(d)
            ok = 0.0 <= r.risk_score <= 100.0
            if not ok:
                print(f"  {cls} @ conf={conf}: score={r.risk_score} OUT OF BOUNDS")
                all_ok = False
            else:
                print(f"  {cls:20s} @ conf={conf:.3f} -> risk={r.risk_score:6.1f}  OK")
    return all_ok


def test_monotonicity_with_confidence():
    """Higher confidence -> higher risk for the same class."""
    scorer = RiskScorer()
    classes = [BENIGN, PORT_SCAN, RECONNAISSANCE, BRUTE_FORCE, DOS]

    all_ok = True
    for cls in classes:
        r_low = scorer.score(make_detection(cls, 0.10))
        r_mid = scorer.score(make_detection(cls, 0.50))
        r_high = scorer.score(make_detection(cls, 0.90))

        ok = r_low.risk_score <= r_mid.risk_score <= r_high.risk_score

        print(f"  {cls:20s}  low={r_low.risk_score:6.1f}  mid={r_mid.risk_score:6.1f}  high={r_high.risk_score:6.1f}  -> {'OK' if ok else 'FAIL'}")
        if not ok:
            all_ok = False
    return all_ok


def test_invalid_confidence_clamped():
    """Negative and >1 confidence should be clamped to [0, 1]."""
    scorer = RiskScorer()
    all_ok = True

    # Negative confidence → should clamp to 0
    d_neg = make_detection(DOS, -0.5)
    r_neg = scorer.score(d_neg)
    base, ceiling = RISK_CONFIG[DOS]["base"], RISK_CONFIG[DOS]["ceiling"]
    expected_neg = round(base + (ceiling - base) * 0.0, 1)
    ok_neg = r_neg.risk_score == expected_neg
    print(f"  DOS conf=-0.5 -> clamped to 0 -> risk={r_neg.risk_score} (expected {expected_neg}): {'OK' if ok_neg else 'FAIL'}")
    all_ok = all_ok and ok_neg

    # Confidence > 1 -> should clamp to 1
    d_over = make_detection(DOS, 1.5)
    r_over = scorer.score(d_over)
    expected_over = round(base + (ceiling - base) * 1.0, 1)
    ok_over = r_over.risk_score == expected_over
    print(f"  DOS conf=1.5  -> clamped to 1 -> risk={r_over.risk_score} (expected {expected_over}): {'OK' if ok_over else 'FAIL'}")
    all_ok = all_ok and ok_over

    return all_ok


def test_unknown_prediction():
    """Unknown prediction class should raise ValueError."""
    scorer = RiskScorer()
    d = make_detection("UNKNOWN_ATTACK", 0.5)
    try:
        scorer.score(d)
        print("  Expected ValueError but no exception raised: FAIL")
        return False
    except ValueError as e:
        print(f"  ValueError raised: {e}")
        print("  Result: OK")
        return True


def test_riskresult_structure():
    """RiskResult is a dataclass with all required fields and types."""
    scorer = RiskScorer()
    d = make_detection(DOS, 0.85)
    r = scorer.score(d)

    print(f"  risk_score:    {r.risk_score} ({type(r.risk_score).__name__})")
    print(f"  severity:      {r.severity} ({type(r.severity).__name__})")
    print(f"  prediction:    {r.prediction} ({type(r.prediction).__name__})")
    print(f"  confidence:    {r.confidence} ({type(r.confidence).__name__})")
    print(f"  explanation:   {r.explanation[:80]}... ({type(r.explanation).__name__})")
    print(f"  rule_reason:   {r.rule_reason[:80]}... ({type(r.rule_reason).__name__})")

    checks = [
        ("is dataclass", is_dataclass(r)),
        ("risk_score is float/int", isinstance(r.risk_score, (int, float))),
        ("severity is str", isinstance(r.severity, str)),
        ("prediction is str", isinstance(r.prediction, str)),
        ("confidence is float/int", isinstance(r.confidence, (int, float))),
        ("explanation is str", isinstance(r.explanation, str)),
        ("rule_reason is str", isinstance(r.rule_reason, str)),
        ("risk_score in [0,100]", 0.0 <= r.risk_score <= 100.0),
        ("confidence in [0,1]", 0.0 <= r.confidence <= 1.0),
        ("explanation non-empty", len(r.explanation) > 0),
    ]

    all_ok = True
    for desc, check in checks:
        print(f"  {desc}: {check}")
        if not check:
            all_ok = False
    return all_ok


def test_class_ordering():
    """DOS > BRUTE_FORCE > RECONNAISSANCE > PORT_SCAN > BENIGN at same confidence."""
    scorer = RiskScorer()
    conf = 0.75

    r_dos = scorer.score(make_detection(DOS, conf))
    r_bf = scorer.score(make_detection(BRUTE_FORCE, conf))
    r_recon = scorer.score(make_detection(RECONNAISSANCE, conf))
    r_ps = scorer.score(make_detection(PORT_SCAN, conf))
    r_benign = scorer.score(make_detection(BENIGN, conf))

    print(f"  BENIGN:       {r_benign.risk_score}")
    print(f"  PORT_SCAN:    {r_ps.risk_score}")
    print(f"  RECONNAISSANCE: {r_recon.risk_score}")
    print(f"  BRUTE_FORCE:  {r_bf.risk_score}")
    print(f"  DOS:          {r_dos.risk_score}")

    ok = (
        r_benign.risk_score < r_ps.risk_score
        < r_recon.risk_score
        < r_bf.risk_score
        < r_dos.risk_score
    )
    return ok


def test_custom_risk_config():
    """RiskScorer accepts a custom risk_config."""
    custom = dict(RISK_CONFIG)
    custom[BENIGN] = {"base": 10, "ceiling": 20}
    scorer = RiskScorer(risk_config=custom)
    d = make_detection(BENIGN, 0.5)
    r = scorer.score(d)
    expected = round(10 + (20 - 10) * 0.5, 1)  # = 15.0
    print(f"  Custom BENIGN @ 0.5 -> {r.risk_score} (expected {expected})")
    return r.risk_score == expected


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("NIDS RISK SCORER TESTS")
    print("=" * 60 + "\n")

    tests = [
        ("BENIGN low confidence", test_benign_low_confidence),
        ("BENIGN high confidence", test_benign_high_confidence),
        ("PORT_SCAN low", test_port_scan_low),
        ("PORT_SCAN high", test_port_scan_high),
        ("BRUTE_FORCE low", test_brute_force_low),
        ("BRUTE_FORCE high", test_brute_force_high),
        ("DOS low", test_dos_low),
        ("DOS high", test_dos_high),
        ("RECONNAISSANCE low", test_reconnaissance_low),
        ("RECONNAISSANCE high", test_reconnaissance_high),
        ("Score boundaries [0, 100]", test_score_boundaries),
        ("Monotonicity with confidence", test_monotonicity_with_confidence),
        ("Invalid confidence clamping", test_invalid_confidence_clamped),
        ("Unknown prediction handling", test_unknown_prediction),
        ("RiskResult structure", test_riskresult_structure),
        ("Class ordering at same conf", test_class_ordering),
        ("Custom risk config", test_custom_risk_config),
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
