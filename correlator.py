"""
Stage 3: Hybrid Correlation Engine for the NIDS.

Combines the Rule Engine prediction (symbolic, threshold-based) with the
ML model prediction (statistical, learned) into a single, unified
``DetectionResult``.

Integration point in the architecture:

    Rule Engine ─────┐
                      ├──→ CorrelationEngine ──→ (next stages: risk scoring, alerts, dashboard)
    ML Model    ─────┘


Correlation strategy (documented for reproducibility):

  A. Rule + ML agree on the same non-BENIGN class:
     combined_conf = 1 - (1 - rule_conf) * (1 - ml_conf)
     Rationale: probability that *at least one* detector is correct
     when both agree.  This is the classic "probability union" — it
     always exceeds the higher individual confidence.

  B. Rule + ML disagree on two different non-BENIGN classes:
     Use the prediction with higher confidence.
     combined_conf = max(rule_conf, ml_conf) * DISAGREEMENT_PENALTY
     Rationale: both sources detect *something* is wrong, but they
     disagree on the type.  We pick the higher-confidence source
     and apply a penalty to reflect the ambiguity.

  C. Rule says BENIGN but ML detects an attack:
     Use the ML prediction.
     combined_conf = ml_conf * SOURCE_DISAGREEMENT_PENALTY
     Rationale: the ML model may catch patterns the rules don't encode.
     We trust the anomaly signal but reduce confidence because the
     rule engine found nothing.

  D. ML says BENIGN but Rule detects an attack:
     Use the Rule Engine prediction.
     combined_conf = rule_conf * SOURCE_DISAGREEMENT_PENALTY
     Rationale: the rule engine may catch attacks the ML model
     misclassifies as benign.  We trust the rule signal but reduce
     confidence because ML didn't agree.

  E. Both say BENIGN:
     combined_conf = min(rule_conf, ml_conf)
     Rationale: when both say benign, we are confident only if both
     have very low attack confidence.  Since BENIGN confidence is
     defined as 0.0 in the rule engine, the combined result is BENIGN
     with confidence = 1 - max_confidence (where max_confidence is the
     probability of the most suspicious alternative).  For simplicity,
     if both predict BENIGN, the combined confidence is the higher
     of the two (which indicates how "non-bening" the flow feels).

Constants:
    DISAGREEMENT_PENALTY      = 0.85  (both detect attack but differ on class)
    SOURCE_DISAGREEMENT_PENALTY = 0.80  (one detects attack, other says benign)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple, Optional

import numpy as np

from .features import NUMERIC_FEATURE_NAMES
from .rule_engine import RuleResult, BENIGN, ALL_ATTACK_CLASSES
from .model import NIDSModel
from .data_extractor import CLASS_LABELS


# ---------------------------------------------------------------------------
# Tunable correlation constants
# ---------------------------------------------------------------------------

# Penalty applied when both detectors find an attack but classify it
# differently (e.g., Rule says DOS, ML says PORT_SCAN).
DISAGREEMENT_PENALTY: float = 0.85

# Penalty applied when one detector raises an alarm and the other
# says BENIGN.  The alarm (more specific) is trusted, but the
# confidence is reduced to account for the lack of corroboration.
SOURCE_DISAGREEMENT_PENALTY: float = 0.80

# Minimum confidence threshold for an attack prediction to be
# considered "confident enough" to override a BENIGN on the other side.
# If the attacking side's confidence is below this, we still use it
# but the combined confidence will be very low, flagging for review.
MIN_ATTACK_CONFIDENCE: float = 0.1


@dataclass
class DetectionResult:
    """
    Unified detection output combining Rule Engine + ML predictions.

    This is the single result that downstream stages (risk scoring,
    alerting, dashboard) consume.

    Fields (all self-explanatory from names):

        final_prediction   — the consensus attack class
        combined_confidence  — confidence in [0.0, 1.0] of the final prediction
        rule_prediction    — Rule Engine's class
        rule_confidence    — Rule Engine's confidence [0.0, 1.0]
        ml_prediction      — ML model's class
        ml_confidence      — ML model's confidence [0.0, 1.0]
        triggered_rules    — rule names that fired (from Rule Engine)
        ml_top3            — list of (label, probability) for top-3 ML predictions
        explanation        — human-readable description of the correlation logic
    """

    final_prediction: str
    combined_confidence: float
    rule_prediction: str
    rule_confidence: float
    ml_prediction: str
    ml_confidence: float
    triggered_rules: List[str] = field(default_factory=list)
    ml_top3: List[Tuple[str, float]] = field(default_factory=list)
    explanation: str = ""


class CorrelationEngine:
    """
    Hybrid correlation engine that fuses Rule Engine and ML predictions.

    Usage:
        engine = CorrelationEngine(model_path="NIDS/models/nids_model.joblib")
        rule_result = rule_engine.process_flow(flow)
        detection = engine.correlate(flow.get_features(), rule_result)
    """

    def __init__(self, model: Optional[NIDSModel] = None, model_path: Optional[str] = None):
        """
        Initialise the correlation engine.

        Args:
            model:   Pre-loaded NIDSModel instance (if already available).
            model_path: Path to a saved model (alternative to passing model).
        """
        if model is not None:
            self.model = model
        elif model_path is not None:
            self.model = NIDSModel.load(model_path)
        else:
            raise ValueError("Either 'model' or 'model_path' must be provided.")

        if not self.model._is_fitted:
            raise RuntimeError("The provided model has not been trained.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(
        self,
        flow_features: List[float],
        rule_result: RuleResult,
    ) -> DetectionResult:
        """
        Combine a Rule Engine result and ML prediction for a single flow
        into a unified ``DetectionResult``.

        Args:
            flow_features: 18-element feature vector from Flow.get_features().
            rule_result:   RuleResult produced by RuleEngine.process_flow().

        Returns:
            DetectionResult with fused prediction, confidence, and explanation.
        """
        ml_label, ml_conf, ml_top3 = self._get_ml_prediction(flow_features)

        rule_pred = rule_result.rule_prediction
        rule_conf = rule_result.rule_confidence

        # ---- Case A: Agreement (both same non-BENIGN class) ----
        if rule_pred != BENIGN and ml_label == rule_pred:
            combined = 1.0 - (1.0 - rule_conf) * (1.0 - ml_conf)
            combined = min(combined, 0.99)
            return DetectionResult(
                final_prediction=rule_pred,
                combined_confidence=round(combined, 4),
                rule_prediction=rule_pred,
                rule_confidence=round(rule_conf, 4),
                ml_prediction=ml_label,
                ml_confidence=round(ml_conf, 4),
                triggered_rules=list(rule_result.triggered_rules),
                ml_top3=ml_top3,
                explanation=(
                    f"AGREEMENT: Rule Engine and ML both predicted {rule_pred}. "
                    f"Combined confidence = 1-(1-{rule_conf:.3f})(1-{ml_conf:.3f}) = {combined:.4f} "
                    f"(probability union of both detectors)."
                ),
            )

        # ---- Case B: Disagreement (both non-BENIGN, different classes) ----
        if rule_pred != BENIGN and ml_label != BENIGN and rule_pred != ml_label:
            if rule_conf >= ml_conf:
                winner = rule_pred
                winner_conf = rule_conf
                loser = "ML"
                loser_conf = ml_conf
            else:
                winner = ml_label
                winner_conf = ml_conf
                loser = "Rule"
                loser_conf = rule_conf

            combined = winner_conf * DISAGREEMENT_PENALTY
            return DetectionResult(
                final_prediction=winner,
                combined_confidence=round(combined, 4),
                rule_prediction=rule_pred,
                rule_confidence=round(rule_conf, 4),
                ml_prediction=ml_label,
                ml_confidence=round(ml_conf, 4),
                triggered_rules=list(rule_result.triggered_rules),
                ml_top3=ml_top3,
                explanation=(
                    f"DISAGREEMENT (both attack, different classes): Rule={rule_pred}@{rule_conf:.3f}, "
                    f"ML={ml_label}@{ml_conf:.3f}. "
                    f"Selected {winner} (higher confidence {winner_conf:.3f}) with "
                    f"penalty {DISAGREEMENT_PENALTY}: {winner_conf:.3f} × {DISAGREEMENT_PENALTY} = {combined:.4f}."
                ),
            )

        # ---- Case C: Rule says BENIGN, ML detects attack ----
        if rule_pred == BENIGN and ml_label != BENIGN:
            combined = ml_conf * SOURCE_DISAGREEMENT_PENALTY
            return DetectionResult(
                final_prediction=ml_label,
                combined_confidence=round(combined, 4),
                rule_prediction=rule_pred,
                rule_confidence=round(rule_conf, 4),
                ml_prediction=ml_label,
                ml_confidence=round(ml_conf, 4),
                triggered_rules=list(rule_result.triggered_rules),
                ml_top3=ml_top3,
                explanation=(
                    f"ML-ONLY DETECTION: Rule Engine said BENIGN, ML predicted {ml_label}@{ml_conf:.3f}. "
                    f"Trusting ML (anomaly detector) with penalty {SOURCE_DISAGREEMENT_PENALTY}: "
                    f"{ml_conf:.3f} × {SOURCE_DISAGREEMENT_PENALTY} = {combined:.4f}. "
                    f"Rule engine found no triggers."
                ),
            )

        # ---- Case D: ML says BENIGN, Rule detects attack ----
        if ml_label == BENIGN and rule_pred != BENIGN:
            combined = rule_conf * SOURCE_DISAGREEMENT_PENALTY
            return DetectionResult(
                final_prediction=rule_pred,
                combined_confidence=round(combined, 4),
                rule_prediction=rule_pred,
                rule_confidence=round(rule_conf, 4),
                ml_prediction=ml_label,
                ml_confidence=round(ml_conf, 4),
                triggered_rules=list(rule_result.triggered_rules),
                ml_top3=ml_top3,
                explanation=(
                    f"RULE-ONLY DETECTION: ML said BENIGN, Rule Engine predicted {rule_pred}@{rule_conf:.3f}. "
                    f"Trusting Rule Engine with penalty {SOURCE_DISAGREEMENT_PENALTY}: "
                    f"{rule_conf:.3f} × {SOURCE_DISAGREEMENT_PENALTY} = {combined:.4f}. "
                    f"Rule triggers: {rule_result.triggered_rules}."
                ),
            )

        # ---- Case E: Both say BENIGN ----
        combined = min(rule_conf, ml_conf) if rule_conf != 0.0 else ml_conf
        return DetectionResult(
            final_prediction=BENIGN,
            combined_confidence=round(combined, 4),
            rule_prediction=rule_pred,
            rule_confidence=round(rule_conf, 4),
            ml_prediction=ml_label,
            ml_confidence=round(ml_conf, 4),
            triggered_rules=list(rule_result.triggered_rules),
            ml_top3=ml_top3,
            explanation=(
                f"BENIGN: Both Rule Engine and ML predicted BENIGN. "
                f"Rule confidence={rule_conf:.3f}, ML confidence={ml_conf:.3f}. "
                f"Combined = min({rule_conf:.3f}, {ml_conf:.3f}) = {combined:.4f}. "
                f"Low combined confidence means benign traffic."
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_ml_prediction(
        self,
        flow_features: List[float],
    ) -> Tuple[str, float, List[Tuple[str, float]]]:
        """
        Get ML prediction, confidence, and top-3 labels with probabilities.

        Returns:
            (top_label, top_confidence, top3_list)
        """
        arr = np.asarray(flow_features, dtype=np.float64).reshape(1, -1)
        arr_scaled = self.model.scaler.transform(arr)
        probs = self.model.clf.predict_proba(arr_scaled)[0]

        # Build (label, prob) pairs using the classifier's actual classes_
        # (integer values) so that probabilities are correctly aligned with
        # label names regardless of which classes are present in training.
        label_probs: List[Tuple[str, float]] = []
        for class_val, prob in zip(self.model.clf.classes_, probs):
            label = CLASS_LABELS[int(class_val)]
            label_probs.append((label, float(prob)))

        label_probs.sort(key=lambda x: x[1], reverse=True)

        top_label, top_conf = label_probs[0]
        top3 = [(lbl, round(prob, 4)) for lbl, prob in label_probs[:3]]

        return top_label, top_conf, top3


__all__ = [
    "DetectionResult",
    "CorrelationEngine",
    "DISAGREEMENT_PENALTY",
    "SOURCE_DISAGREEMENT_PENALTY",
    "MIN_ATTACK_CONFIDENCE",
]
