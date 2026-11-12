"""
STAGE 11.3: Evaluation Engine
===============================

Calculates classification and operational metrics from labeled evaluation
datasets. Supports both flow-level and session-level evaluation.

Metrics:
  - Classification: accuracy, precision, recall, F1, macro F1, weighted F1,
    confusion matrix, per-class support, FPR, FNR
  - Operational: alerts per hour, false alerts per hour, detection latency,
    flow processing failures
  - Confidence: prediction confidence distributions, per-class confidence
  - Distribution: feature distribution statistics, train-vs-eval comparison
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

@dataclass
class ClassificationMetrics:
    """Container for classification metrics."""
    accuracy: float = 0.0
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0
    weighted_precision: float = 0.0
    weighted_recall: float = 0.0
    weighted_f1: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=list)
    per_class: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "macro_precision": self.macro_precision,
            "macro_recall": self.macro_recall,
            "macro_f1": self.macro_f1,
            "weighted_precision": self.weighted_precision,
            "weighted_recall": self.weighted_recall,
            "weighted_f1": self.weighted_f1,
            "confusion_matrix": self.confusion_matrix,
            "per_class": self.per_class,
        }


@dataclass
class OperationalMetrics:
    """Container for operational metrics."""
    total_records: int = 0
    alerts_per_hour: float = 0.0
    false_alerts_per_hour: float = 0.0
    detection_latency_mean: float = 0.0
    detection_latency_p95: float = 0.0
    flow_processing_failures: int = 0
    capture_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_records": self.total_records,
            "alerts_per_hour": self.alerts_per_hour,
            "false_alerts_per_hour": self.false_alerts_per_hour,
            "detection_latency_mean": self.detection_latency_mean,
            "detection_latency_p95": self.detection_latency_p95,
            "flow_processing_failures": self.flow_processing_failures,
            "capture_duration_seconds": self.capture_duration_duration_seconds,
        }


@dataclass
class ConfidenceMetrics:
    """Container for confidence/probability analysis."""
    mean_confidence_correct: float = 0.0
    mean_confidence_incorrect: float = 0.0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    per_class_confidence: Dict[str, Dict[str, float]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean_confidence_correct": self.mean_confidence_correct,
            "mean_confidence_incorrect": self.mean_confidence_incorrect,
            "confidence_distribution": self.confidence_distribution,
            "per_class_confidence": self.per_class_confidence,
        }


@dataclass
class DistributionMetrics:
    """Container for feature distribution analysis."""
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    train_vs_eval_wasserstein: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "train_vs_eval_wasserstein": self.train_vs_eval_wasserstein,
        }


@dataclass
class EvaluationResult:
    """Complete evaluation result."""
    classification: ClassificationMetrics = field(default_factory=ClassificationMetrics)
    operational: OperationalMetrics = field(default_factory=OperationalMetrics)
    confidence: ConfidenceMetrics = field(default_factory=ConfidenceMetrics)
    distribution: DistributionMetrics = field(default_factory=DistributionMetrics)
    dataset_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.to_dict(),
            "operational": self.operational.to_dict(),
            "confidence": self.confidence.to_dict(),
            "distribution": self.distribution.to_dict(),
            "dataset_info": self.dataset_info,
        }


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------

class EvaluationEngine:
    """
    Computes metrics from an EvaluationDataset.

    The engine is a pure function of the dataset — it does not modify
    the dataset or run the NIDS model. Model predictions must be
    pre-populated in the dataset records before evaluation.
    """

    def __init__(self, dataset: EvaluationDataset):
        self.dataset = dataset

    def _get_valid_records(self) -> List[EvaluationRecord]:
        """Return only VALID records with model predictions."""
        records = []
        for r in self.dataset.records:
            if r.verdict() == ValidationVerdict.VALID and r.model_prediction is not None:
                records.append(r)
        return records

    def compute_classification(self) -> ClassificationMetrics:
        """Compute classification metrics from valid records."""
        records = self._get_valid_records()
        if not records:
            return ClassificationMetrics()

        y_true = [r.ground_truth_label for r in records]
        y_pred = [r.model_prediction for r in records]

        cm = confusion_matrix(y_true, y_pred, labels=CLASS_LABELS).tolist()

        report = classification_report(
            y_true, y_pred, target_names=CLASS_LABELS, zero_division=0, output_dict=True
        )

        per_class = {}
        for lbl in CLASS_LABELS:
            if lbl in report:
                r = report[lbl]
                per_class[lbl] = {
                    "precision": r["precision"],
                    "recall": r["recall"],
                    "f1": r["f1-score"],
                    "support": int(r["support"]),
                    "fpr": self._compute_fpr(cm, CLASS_LABELS.index(lbl)),
                    "fnr": self._compute_fnr(cm, CLASS_LABELS.index(lbl)),
                }

        return ClassificationMetrics(
            accuracy=float(accuracy_score(y_true, y_pred)),
            macro_precision=float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
            macro_recall=float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
            macro_f1=float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            weighted_precision=float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
            weighted_recall=float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
            weighted_f1=float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
            confusion_matrix=cm,
            per_class=per_class,
        )

    def _compute_fpr(self, cm: List[List[int]], class_idx: int) -> float:
        """Compute False Positive Rate for a given class."""
        tn = sum(cm[i][j] for i in range(len(cm)) if i != class_idx for j in range(len(cm)) if j != class_idx)
        fp = sum(cm[i][class_idx] for i in range(len(cm)) if i != class_idx)
        return fp / (fp + tn) if (fp + tn) > 0 else 0.0

    def _compute_fnr(self, cm: List[List[int]], class_idx: int) -> float:
        """Compute False Negative Rate for a given class."""
        tp = cm[class_idx][class_idx]
        fn = sum(cm[class_idx][j] for j in range(len(cm)) if j != class_idx)
        return fn / (fn + tp) if (fn + tp) > 0 else 0.0

    def compute_operational(self) -> OperationalMetrics:
        """Compute operational metrics from valid records."""
        records = self._get_valid_records()
        if not records:
            return OperationalMetrics()

        # Alerts per hour
        timestamps = [r.collection_timestamp for r in records if r.collection_timestamp > 0]
        if len(timestamps) >= 2:
            duration_hours = (max(timestamps) - min(timestamps)) / 3600.0
        else:
            duration_hours = 1.0

        # Count "alerts" as records where model prediction != BENIGN
        alerts = sum(1 for r in records if r.model_prediction != "BENIGN")
        false_alerts = sum(1 for r in records if r.model_prediction != "BENIGN" and r.ground_truth_label == "BENIGN")

        alerts_per_hour = alerts / duration_hours if duration_hours > 0 else 0.0
        false_alerts_per_hour = false_alerts / duration_hours if duration_hours > 0 else 0.0

        # Detection latency (where model_prediction != BENIGN and ground truth is attack)
        latencies = []
        for r in records:
            if r.model_prediction != "BENIGN" and r.ground_truth_label != "BENIGN":
                # Latency approximated as flow duration (time from first to last packet)
                if r.flow_duration is not None and r.flow_duration >= 0:
                    latencies.append(r.flow_duration)

        latency_mean = float(np.mean(latencies)) if latencies else 0.0
        latency_p95 = float(np.percentile(latencies, 95)) if latencies else 0.0

        return OperationalMetrics(
            total_records=len(records),
            alerts_per_hour=alerts_per_hour,
            false_alerts_per_hour=false_alerts_per_hour,
            detection_latency_mean=latency_mean,
            detection_latency_p95=latency_p95,
            flow_processing_failures=0,  # Populated if capture metadata available
            capture_duration_seconds=duration_hours * 3600.0,
        )

    def compute_confidence(self) -> ConfidenceMetrics:
        """Compute confidence distribution metrics."""
        records = self._get_valid_records()
        if not records:
            return ConfidenceMetrics()

        correct_conf = []
        incorrect_conf = []
        bins = {
            "[0.0, 0.2)": 0,
            "[0.2, 0.4)": 0,
            "[0.4, 0.6)": 0,
            "[0.6, 0.8)": 0,
            "[0.8, 1.0]": 0,
        }

        for r in records:
            if r.model_confidence is None:
                continue
            conf = r.model_confidence
            if r.model_prediction == r.ground_truth_label:
                correct_conf.append(conf)
            else:
                incorrect_conf.append(conf)

            # Bin
            if conf < 0.2:
                bins["[0.0, 0.2)"] += 1
            elif conf < 0.4:
                bins["[0.2, 0.4)"] += 1
            elif conf < 0.6:
                bins["[0.4, 0.6)"] += 1
            elif conf < 0.8:
                bins["[0.6, 0.8)"] += 1
            else:
                bins["[0.8, 1.0]"] += 1

        # Per-class confidence
        per_class_conf: Dict[str, Dict[str, float]] = {}
        for lbl in CLASS_LABELS:
            lbl_records = [r for r in records if r.ground_truth_label == lbl]
            if lbl_records:
                confs = [r.model_confidence for r in lbl_records if r.model_confidence is not None]
                per_class_conf[lbl] = {
                    "mean_confidence": float(np.mean(confs)) if confs else 0.0,
                    "std_confidence": float(np.std(confs)) if confs else 0.0,
                    "count": len(confs),
                }

        return ConfidenceMetrics(
            mean_confidence_correct=float(np.mean(correct_conf)) if correct_conf else 0.0,
            mean_confidence_incorrect=float(np.mean(incorrect_conf)) if incorrect_conf else 0.0,
            confidence_distribution=bins,
            per_class_confidence=per_class_conf,
        )

    def compute_distribution(self, train_features: Optional[np.ndarray] = None) -> DistributionMetrics:
        """
        Compute feature distribution statistics.

        Args:
            train_features: Optional array of training features (n_train, 18)
                           to compute Wasserstein distances.
        """
        records = self._get_valid_records()
        if not records:
            return DistributionMetrics()

        features = np.array([r.features for r in records])
        means = {name: float(np.mean(features[:, i])) for i, name in enumerate(CLASS_LABELS[:18])}
        stds = {name: float(np.std(features[:, i])) for i, name in enumerate(CLASS_LABELS[:18])}

        wasserstein = {}
        if train_features is not None:
            from scipy.stats import wasserstein_distance
            for i, name in enumerate(CLASS_LABELS[:18]):
                wd = wasserstein_distance(train_features[:, i], features[:, i])
                wasserstein[name] = float(wd)

        return DistributionMetrics(
            feature_means=means,
            feature_stds=stds,
            train_vs_eval_wasserstein=wasserstein,
        )

    def evaluate(self, train_features: Optional[np.ndarray] = None) -> EvaluationResult:
        """
        Run full evaluation and return results.

        Args:
            train_features: Optional training features for distribution comparison.
        """
        classification = self.compute_classification()
        operational = self.compute_operational()
        confidence = self.compute_confidence()
        distribution = self.compute_distribution(train_features)

        dataset_info = {
            "name": self.dataset.name,
            "total_records": len(self.dataset.records),
            "valid_records": len(self._get_valid_records()),
            "validation_summary": self.dataset.validation_summary(),
            "label_distribution": self.dataset.label_distribution(),
            "sessions": list(self.dataset.sessions.keys()),
        }

        return EvaluationResult(
            classification=classification,
            operational=operational,
            confidence=confidence,
            distribution=distribution,
            dataset_info=dataset_info,
        )

    def report(self, result: Optional[EvaluationResult] = None) -> str:
        """Generate a human-readable evaluation report."""
        if result is None:
            result = self.evaluate()

        lines = []
        lines.append("=" * 70)
        lines.append("EVALUATION REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Dataset info
        lines.append("DATASET INFO")
        lines.append("-" * 40)
        for k, v in result.dataset_info.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

        # Classification
        c = result.classification
        lines.append("CLASSIFICATION METRICS")
        lines.append("-" * 40)
        lines.append(f"  Accuracy          : {c.accuracy:.4f}")
        lines.append(f"  Macro Precision   : {c.macro_precision:.4f}")
        lines.append(f"  Macro Recall      : {c.macro_recall:.4f}")
        lines.append(f"  Macro F1          : {c.macro_f1:.4f}")
        lines.append(f"  Weighted Precision: {c.weighted_precision:.4f}")
        lines.append(f"  Weighted Recall   : {c.weighted_recall:.4f}")
        lines.append(f"  Weighted F1       : {c.weighted_f1:.4f}")
        lines.append("")
        lines.append("  Per-class metrics:")
        for lbl in CLASS_LABELS:
            if lbl in c.per_class:
                pc = c.per_class[lbl]
                lines.append(
                    f"    {lbl:20s}: P={pc['precision']:.4f}  R={pc['recall']:.4f}  "
                    f"F1={pc['f1']:.4f}  FPR={pc['fpr']:.4f}  FNR={pc['fnr']:.4f}  support={pc['support']}"
                )
        lines.append("")
        lines.append("  Confusion Matrix:")
        header = "      " + "  ".join(f"{c:10s}" for c in CLASS_LABELS)
        lines.append(header)
        for i, row in enumerate(c.confusion_matrix):
            lines.append(f"{CLASS_LABELS[i]:10s}" + "  ".join(f"{int(v):4d}" for v in row))
        lines.append("")

        # Operational
        o = result.operational
        lines.append("OPERATIONAL METRICS")
        lines.append("-" * 40)
        lines.append(f"  Total records             : {o.total_records}")
        lines.append(f"  Alerts per hour           : {o.alerts_per_hour:.2f}")
        lines.append(f"  False alerts per hour     : {o.false_alerts_per_hour:.2f}")
        lines.append(f"  Detection latency (mean)  : {o.detection_latency_mean:.4f}s")
        lines.append(f"  Detection latency (p95)   : {o.detection_latency_p95:.4f}s")
        lines.append(f"  Capture duration          : {o.capture_duration_seconds:.1f}s")
        lines.append("")

        # Confidence
        conf = result.confidence
        lines.append("CONFIDENCE METRICS")
        lines.append("-" * 40)
        lines.append(f"  Mean confidence (correct)   : {conf.mean_confidence_correct:.4f}")
        lines.append(f"  Mean confidence (incorrect) : {conf.mean_confidence_incorrect:.4f}")
        lines.append("  Confidence distribution:")
        for bucket, count in conf.confidence_distribution.items():
            lines.append(f"    {bucket}: {count}")
        lines.append("")

        # Distribution
        d = result.distribution
        if d.train_vs_eval_wasserstein:
            lines.append("DISTRIBUTION SHIFT (Train vs Eval)")
            lines.append("-" * 40)
            for feat, wd in sorted(d.train_vs_eval_wasserstein.items(), key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"  {feat:25s}: {wd:.4f}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)
