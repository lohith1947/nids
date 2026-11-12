"""
Stage 4 (partial): Risk Scorer for the NIDS.

Consumes a DetectionResult (produced by CorrelationEngine) and produces a
deterministic risk score in the range [0, 100] together with a structured
RiskResult for downstream alerting and dashboard display.

Risk model
----------
Each attack class is assigned a base risk and a risk ceiling.  The final
score is a linear interpolation between the two as a function of the
DetectionResult's combined confidence (0.0 – 1.0):

    risk = base_risk[prediction] + (ceiling_risk[prediction] - base_risk[prediction]) * confidence

Rationale for the numeric choices
--------------------------------
The base/ceiling pairs are derived from the SEVERITY_MAP labels already
defined in config.py, so that the numeric scale respects the qualitative
ordering established there:

    BENIGN           INFORMATIONAL → base=0,   ceiling=5    (always negligible)
    PORT_SCAN        MEDIUM        → base=15,  ceiling=35   (probe, limited impact)
    RECONNAISSANCE   MEDIUM        → base=20,  ceiling=40   (active discovery)
    BRUTE_FORCE      HIGH          → base=40,  ceiling=70   (credential attack)
    DOS              CRITICAL      → base=80,  ceiling=100   (immediate disruption)

Properties guaranteed by this formula:
  - 0 <= risk <= 100  for every valid input (confidence is clamped to [0, 1])
  - BENIGN always receives a risk <= 5
  - DOS always receives the highest risk range (80–100)
  - risk increases monotonically with confidence for the same class
  - classes are strictly ordered: BENIGN < PORT_SCAN < RECONNAISSANCE < BRUTE_FORCE < DOS

The existing SEVERITY_MAP in config.py is preserved unchanged.  A separate
RISK_CONFIG dictionary (added here, not in config.py) carries the numeric
base/ceiling values so the semantic labels retain their original meaning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .config import SEVERITY_MAP
from .rule_engine import (
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
    ALL_ATTACK_CLASSES,
)


# ---------------------------------------------------------------------------
# Numeric risk configuration (separate from SEVERITY_MAP)
# ---------------------------------------------------------------------------
# Maps each attack class to {base, ceiling}.  Risk = base + (ceiling - base) * conf.
RISK_CONFIG: Dict[str, Dict[str, int]] = {
    BENIGN:           {"base": 0,   "ceiling": 5},
    PORT_SCAN:        {"base": 15,  "ceiling": 35},
    RECONNAISSANCE:   {"base": 20,  "ceiling": 40},
    BRUTE_FORCE:      {"base": 40,  "ceiling": 70},
    DOS:              {"base": 80,  "ceiling": 100},
}

# Ordered list of attack classes for display / validation
RISK_ORDER: List[str] = [BENIGN, PORT_SCAN, RECONNAISSANCE, BRUTE_FORCE, DOS]


@dataclass
class RiskResult:
    """
    Structured output of the RiskScorer.

    Attributes:
        risk_score:    Numeric risk in [0, 100], rounded to 1 decimal.
        severity:      Severity label from SEVERITY_MAP (INFORMATIONAL/MEDIUM/HIGH/CRITICAL).
        prediction:    The final detection class that was scored.
        confidence:    The combined confidence (0.0–1.0) used for scoring.
        explanation:   Human-readable description of how the score was derived.
        rule_reason:   Optional, carried through from the DetectionResult.
    """
    risk_score: float
    severity: str
    prediction: str
    confidence: float
    explanation: str
    rule_reason: str = ""


class RiskScorer:
    """
    Converts a DetectionResult into a RiskResult with a deterministic 0–100 score.

    The scorer is stateless — each call to ``score()`` is independent and
    deterministic given the same DetectionResult.
    """

    def __init__(self, risk_config: Dict[str, Dict[str, int]] = None):
        """
        Initialise the scorer with an optional custom risk configuration.

        Args:
            risk_config: Optional override for RISK_CONFIG.  If not provided,
                         the default RISK_CONFIG is used.
        """
        self.risk_config = risk_config if risk_config is not None else RISK_CONFIG

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, detection) -> RiskResult:
        """
        Compute a risk score from a DetectionResult.

        Args:
            detection: A DetectionResult from CorrelationEngine.

        Returns:
            RiskResult with risk_score in [0, 100], severity label, and
            a human-readable explanation.

        Raises:
            ValueError: If the prediction class is not in RISK_CONFIG.
        """
        prediction = detection.final_prediction

        cfg = self.risk_config.get(prediction)
        if cfg is None:
            raise ValueError(
                f"Unknown prediction class '{prediction}'. "
                f"Expected one of: {list(self.risk_config.keys())}"
            )

        # --- Clamp confidence to [0, 1] for safety ---
        raw_conf = detection.combined_confidence
        if raw_conf < 0.0:
            confidence = 0.0
        elif raw_conf > 1.0:
            confidence = 1.0
        else:
            confidence = raw_conf

        base = cfg["base"]
        ceiling = cfg["ceiling"]

        # Linear interpolation: risk = base + (ceiling - base) * confidence
        risk = base + (ceiling - base) * confidence

        # Round to 1 decimal place
        risk_score = round(risk, 1)

        # Guard against floating-point edge cases
        if risk_score > 100.0:
            risk_score = 100.0
        elif risk_score < 0.0:
            risk_score = 0.0

        severity = SEVERITY_MAP.get(prediction, "UNKNOWN")

        explanation = (
            f"Risk for {prediction}: base={base}, ceiling={ceiling}, "
            f"confidence={confidence:.4f} (combined_confidence from DetectionResult). "
            f"Formula: {base} + ({ceiling} - {base}) * {confidence:.4f} = {risk_score:.1f}. "
            f"Severity label: {severity}."
        )

        return RiskResult(
            risk_score=risk_score,
            severity=severity,
            prediction=prediction,
            confidence=confidence,
            explanation=explanation,
            rule_reason=detection.explanation,
        )

    def risk_range(self, prediction: str) -> tuple:
        """
        Return the (base, ceiling) risk range for a given prediction class.

        This is useful for dashboards that want to display expected
        risk bands per class.
        """
        cfg = self.risk_config.get(prediction)
        if cfg is None:
            raise ValueError(
                f"Unknown prediction class '{prediction}'. "
                f"Expected one of: {list(self.risk_config.keys())}"
            )
        return cfg["base"], cfg["ceiling"]


__all__ = [
    "RiskScorer",
    "RiskResult",
    "RISK_CONFIG",
    "RISK_ORDER",
]
