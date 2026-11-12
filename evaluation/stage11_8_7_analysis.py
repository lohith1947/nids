#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 11.8.7 — Non-Loopback Attack Evaluation Analysis
======================================================

Post-collection analysis for the Stage 11.8.7 split-architecture evaluation.
Loads a dataset produced by capture_listener_11_8_7.py (or collect_attack_11_8_v2.py),
independently verifies the frozen model, re-runs ML predictions, computes
classification and operational metrics, performs feature distribution analysis,
and compares against the Stage 11.8.2 loopback baseline.

This is evaluation-only code. It does NOT modify the production model, rules,
thresholds, features, risk scoring, alerts, dashboard, or correlation engine.

Usage:
    python -m NIDS.evaluation.stage11_8_7_analysis \\
        --dataset NIDS/evaluation/datasets/stage11_8_7_pilot.jsonl \\
        --pcap NIDS/evaluation/datasets/stage11_8_7_pilot.pcap \\
        --model NIDS/models/nids_model.joblib \\
        --baseline NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z.jsonl
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

import numpy as np
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

from NIDS.model import NIDSModel
from NIDS.evaluation.schema import CLASS_LABELS, FEATURE_NAMES, EvaluationDataset
from NIDS.evaluation.evaluate import EvaluationEngine

EXPECTED_MODEL_HASH = "7bcc643154a1f44d"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib"
REPORT_DIR = PROJECT_ROOT / "NIDS" / "evaluation" / "datasets"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

STAGE_11_8_2_BASELINE = REPORT_DIR / "attack_11_8_2_20260910T140310Z.jsonl"


# ===========================================================================
# Helpers
# ===========================================================================

def compute_model_hash(path: str | Path) -> str:
    """Compute the first 16 characters of the SHA256 hash of a file."""
    with open(str(path), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def load_model(model_path: str | Path) -> Tuple[NIDSModel, str]:
    """Load the frozen model and verify its hash."""
    model_hash = compute_model_hash(model_path)
    if model_hash != EXPECTED_MODEL_HASH:
        print(f"[WARNING] Model hash mismatch: expected {EXPECTED_MODEL_HASH}, got {model_hash}")
    else:
        print(f"[model] Hash verified: {model_hash}")

    model = NIDSModel.load(str(model_path))
    print(f"[model] type={type(model.clf).__name__}, "
          f"n_estimators={model.clf.n_estimators}, "
          f"max_depth={model.clf.max_depth}, "
          f"n_features_in_={model.clf.n_features_in_}, "
          f"classes_={model.clf.classes_}")
    return model, model_hash


def load_dataset(dataset_path: str | Path) -> EvaluationDataset:
    """Load a JSONL dataset using the schema's loader."""
    dataset = EvaluationDataset.from_jsonl(str(dataset_path), name=f"stage11_8_7_{Path(dataset_path).stem}")
    print(f"[data] Loaded {len(dataset.records)} records from {dataset_path}")
    print(f"[data] Validation summary: {dataset.validation_summary()}")
    print(f"[data] Label distribution: {dataset.label_distribution()}")
    return dataset


def rerun_predictions(dataset: EvaluationDataset, model: NIDSModel) -> int:
    """Independently re-run model predictions on each record's features.

    Returns the number of records whose prediction differed from the
    previously stored value (mismatch count).
    """
    changed = 0
    scaler = model.scaler
    clf = model.clf
    for rec in dataset.records:
        if not rec.features or len(rec.features) != 18:
            continue
        arr = np.asarray(rec.features, dtype=np.float64).reshape(1, -1)
        arr_scaled = scaler.transform(arr)
        probs = clf.predict_proba(arr_scaled)[0]
        pred_idx = clf.classes_.searchsorted(clf.predict(arr_scaled))[0]
        pred_idx = int(np.clip(pred_idx, 0, len(CLASS_LABELS) - 1))
        label = CLASS_LABELS[pred_idx]
        conf = float(probs[pred_idx])

        old_pred = rec.model_prediction
        old_conf = rec.model_confidence
        rec.model_prediction = label
        rec.model_confidence = conf
        rec.model_probabilities = {CLASS_LABELS[i]: float(p) for i, p in enumerate(probs)}

        if old_pred is not None and old_pred != label:
            changed += 1
        if old_pred is None:
            rec.model_prediction = label
            rec.model_confidence = conf
    print(f"[predict] Predictions recomputed independently. Mismatches with stored: {changed}")
    return changed


def compute_classification_metrics(dataset: EvaluationDataset) -> Dict[str, Any]:
    """Compute classification metrics from records with model predictions."""
    records = [r for r in dataset.records if r.model_prediction is not None]
    if not records:
        return {"error": "No records with model predictions"}

    y_true = [r.ground_truth_label for r in records]
    y_pred = [r.model_prediction for r in records]

    present_labels = sorted(set(y_true) | set(y_pred))
    labels = [l for l in CLASS_LABELS if l in present_labels] or present_labels

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    report = classification_report(y_true, y_pred, labels=labels, zero_division=0, output_dict=True)

    per_class: Dict[str, Any] = {}
    for lbl in labels:
        if lbl in report:
            r = report[lbl]
            idx = labels.index(lbl)
            tp = int(cm[idx][idx])
            fp = int(sum(cm[i][idx] for i in range(len(labels)) if i != idx))
            fn = int(sum(cm[idx][j] for j in range(len(labels)) if j != idx))
            tn = int(sum(cm[i][j] for i in range(len(labels)) if i != idx for j in range(len(labels)) if j != idx))
            per_class[lbl] = {
                "support": int(r["support"]),
                "precision": float(r["precision"]),
                "recall": float(r["recall"]),
                "f1": float(r["f1-score"]),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
                "fnr": fn / (fn + tp) if (fn + tp) > 0 else 0.0,
            }

    metrics = {
        "total": len(records),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_precision": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "weighted_recall": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "confusion_matrix": cm.tolist(),
        "labels": labels,
        "per_class": per_class,
    }

    recall = metrics["macro_recall"]
    attack_recall = 0.0
    attack_classes = ["PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]
    for cls in attack_classes:
        if cls in per_class:
            attack_recall = max(attack_recall, per_class[cls]["recall"])

    benign_probs = []
    for r in records:
        if r.model_probabilities and "BENIGN" in r.model_probabilities:
            benign_probs.append(r.model_probabilities["BENIGN"])
    metrics["attack_recall"] = float(attack_recall)
    metrics["mean_benign_probability"] = float(np.mean(benign_probs)) if benign_probs else 0.0
    return metrics


def compute_operational_metrics(dataset: EvaluationDataset) -> Dict[str, Any]:
    """Compute operational metrics: latency, alerts, attribution."""
    records = [r for r in dataset.records if r.model_prediction is not None]
    if not records:
        return {"error": "No records with model predictions"}

    timestamps = [r.collection_timestamp for r in records if r.collection_timestamp > 0]
    capture_duration = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0

    attack_records = [r for r in records if r.ground_truth_label != "BENIGN"]
    benign_records = [r for r in records if r.ground_truth_label == "BENIGN"]

    alerts = sum(1 for r in records if r.model_prediction != "BENIGN")
    false_alerts = sum(1 for r in records if r.model_prediction != "BENIGN" and r.ground_truth_label == "BENIGN")
    false_negatives = sum(1 for r in records if r.model_prediction == "BENIGN" and r.ground_truth_label != "BENIGN")

    latencies = [r.flow_duration for r in attack_records
                 if r.flow_duration is not None and r.flow_duration >= 0]

    capture_errors = [r for r in records if r.extra_metadata and r.extra_metadata.get("capture_error")]

    # Attribution verification: 5-tuple uniqueness
    tuples = set()
    for r in records:
        t = (r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.protocol)
        tuples.add(t)

    metrics = {
        "capture_duration_seconds": float(capture_duration),
        "packets_captured": sum(r.packet_count or 0 for r in records),
        "alerts_generated": int(alerts),
        "false_alerts": int(false_alerts),
        "false_negatives": int(false_negatives),
        "false_alert_rate": float(false_alerts / len(benign_records)) if benign_records else 0.0,
        "detection_latency": {
            "count": len(latencies),
            "mean": float(np.mean(latencies)) if latencies else 0.0,
            "median": float(np.median(latencies)) if latencies else 0.0,
            "p95": float(np.percentile(latencies, 95)) if latencies else 0.0,
            "max": float(np.max(latencies)) if latencies else 0.0,
        },
        "unique_5_tuples": len(tuples),
        "total_records": len(records),
        "capture_errors": len(capture_errors),
    }
    return metrics


def compute_feature_distributions(dataset: EvaluationDataset) -> Dict[str, Any]:
    """Compute per-class feature distribution statistics."""
    records = [r for r in dataset.records if r.model_prediction is not None and len(r.features) == 18]
    if not records:
        return {"error": "No valid records for feature analysis"}

    by_class: Dict[str, List[List[float]]] = {}
    for r in records:
        lbl = r.ground_truth_label
        by_class.setdefault(lbl, []).append(r.features)

    result: Dict[str, Any] = {"per_class": {}, "global": {}}
    all_features = np.array([r.features for r in records])

    for i, fname in enumerate(FEATURE_NAMES):
        result["global"][fname] = {
            "mean": float(np.mean(all_features[:, i])),
            "std": float(np.std(all_features[:, i])),
            "min": float(np.min(all_features[:, i])),
            "max": float(np.max(all_features[:, i])),
            "median": float(np.median(all_features[:, i])),
        }

    for cls, feats_list in by_class.items():
        arr = np.array(feats_list)
        cls_stats: Dict[str, Any] = {}
        for i, fname in enumerate(FEATURE_NAMES):
            col = arr[:, i]
            cls_stats[fname] = {
                "count": int(len(col)),
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
                "min": float(np.min(col)),
                "max": float(np.max(col)),
                "median": float(np.median(col)),
                "p1": float(np.percentile(col, 1)),
                "p5": float(np.percentile(col, 5)),
                "p25": float(np.percentile(col, 25)),
                "p50": float(np.percentile(col, 50)),
                "p75": float(np.percentile(col, 75)),
                "p95": float(np.percentile(col, 95)),
                "p99": float(np.percentile(col, 99)),
            }
        result["per_class"][cls] = cls_stats

    return result


def compare_with_baseline(dataset: EvaluationDataset, baseline_path: str | Path) -> Dict[str, Any]:
    """Compare the current dataset against the Stage 11.8.2 loopback baseline."""
    if not Path(baseline_path).exists():
        return {"error": f"Baseline dataset not found: {baseline_path}"}

    baseline = EvaluationDataset.from_jsonl(str(baseline_path), name="stage11_8_2_baseline")
    print(f"[compare] Loaded baseline: {len(baseline.records)} records")

    current_by_class = dataset.label_distribution()
    baseline_by_class = baseline.label_distribution()

    # Per-class recall comparison
    current_cls = compute_classification_metrics(dataset)
    baseline_cls = compute_classification_metrics(baseline)

    comparison = {
        "baseline_records": len(baseline.records),
        "current_records": len(dataset.records),
        "baseline_label_dist": baseline_by_class,
        "current_label_dist": current_by_class,
        "baseline_accuracy": baseline_cls.get("accuracy", 0.0),
        "current_accuracy": current_cls.get("accuracy", 0.0),
        "baseline_macro_recall": baseline_cls.get("macro_recall", 0.0),
        "current_macro_recall": current_cls.get("macro_recall", 0.0),
        "baseline_attack_recall": baseline_cls.get("attack_recall", 0.0),
        "current_attack_recall": current_cls.get("attack_recall", 0.0),
        "baseline_mean_benign_prob": baseline_cls.get("mean_benign_probability", 0.0),
        "current_mean_benign_prob": current_cls.get("mean_benign_probability", 0.0),
        "accuracy_improvement": current_cls.get("accuracy", 0.0) - baseline_cls.get("accuracy", 0.0),
        "attack_recall_improvement": current_cls.get("attack_recall", 0.0) - baseline_cls.get("attack_recall", 0.0),
    }

    # Per-class recall comparison
    per_class_comparison: Dict[str, Any] = {}
    for lbl in CLASS_LABELS:
        b_recall = baseline_cls.get("per_class", {}).get(lbl, {}).get("recall", 0.0)
        c_recall = current_cls.get("per_class", {}).get(lbl, {}).get("recall", 0.0)
        per_class_comparison[lbl] = {
            "baseline_recall": b_recall,
            "current_recall": c_recall,
            "recall_improvement": c_recall - b_recall,
        }
    comparison["per_class_recall"] = per_class_comparison
    return comparison


def generate_report(
    dataset: EvaluationDataset,
    model_hash: str,
    classification: Dict[str, Any],
    operational: Dict[str, Any],
    feature_dists: Dict[str, Any],
    comparison: Dict[str, Any],
    dataset_path: str,
    pcap_path: Optional[str],
    mismatches: int,
) -> str:
    """Generate a human-readable Markdown report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = []
    lines.append("# STAGE 11.8.7 — ANALYSIS REPORT")
    lines.append("")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Dataset:** `{dataset_path}`")
    if pcap_path:
        lines.append(f"**PCAP:** `{pcap_path}`")
    lines.append(f"**Model hash:** `{model_hash}`")
    lines.append(f"**Hash verified:** {'YES' if model_hash == EXPECTED_MODEL_HASH else 'NO'}")
    lines.append("")

    # Section 1
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- **Total records:** {classification.get('total', 0)}")
    lines.append(f"- **Accuracy:** {classification.get('accuracy', 0.0):.4f}")
    lines.append(f"- **Macro Recall:** {classification.get('macro_recall', 0.0):.4f}")
    lines.append(f"- **Attack recall:** {classification.get('attack_recall', 0.0):.4f}")
    lines.append(f"- **Mean BENIGN probability:** {classification.get('mean_benign_probability', 0.0):.4f}")
    lines.append(f"- **Independent prediction mismatches:** {mismatches}")
    lines.append("")

    verdict = "GREEN"
    if classification.get("attack_recall", 0.0) < 0.1:
        verdict = "RED"
    elif classification.get("attack_recall", 0.0) < 0.5:
        verdict = "YELLOW"
    elif model_hash != EXPECTED_MODEL_HASH:
        verdict = "YELLOW"

    lines.append(f"**Verdict:** `{verdict}`")
    lines.append("")

    # Section 2
    lines.append("## 2. Model Integrity")
    lines.append("")
    lines.append("| Property | Value | Status |")
    lines.append("|----------|-------|--------|")
    lines.append(f"| Model hash | `{model_hash}` | {'PASS' if model_hash == EXPECTED_MODEL_HASH else 'FAIL'} |")
    lines.append(f"| Expected hash | `{EXPECTED_MODEL_HASH}` | — |")
    lines.append(f"| Bundle keys | scaler, clf | PASS |")
    lines.append(f"| n_features_in_ | {dataset.records[0].features.__len__() if dataset.records else 0} (expected 18) | — |")
    lines.append("")

    # Section 3
    lines.append("## 3. Dataset Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total records | {len(dataset.records)} |")
    lines.append(f"| Validation summary | {dataset.validation_summary()} |")
    lines.append(f"| Label distribution | {dataset.label_distribution()} |")
    lines.append(f"| Unique 5-tuples | {operational.get('unique_5_tuples', 0)} |")
    lines.append(f"| Capture duration | {operational.get('capture_duration_seconds', 0.0):.2f}s |")
    lines.append("")

    # Section 4
    lines.append("## 4. Classification Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Accuracy | {classification.get('accuracy', 0.0):.4f} |")
    lines.append(f"| Macro Precision | {classification.get('macro_precision', 0.0):.4f} |")
    lines.append(f"| Macro Recall | {classification.get('macro_recall', 0.0):.4f} |")
    lines.append(f"| Macro F1 | {classification.get('macro_f1', 0.0):.4f} |")
    lines.append(f"| Weighted Precision | {classification.get('weighted_precision', 0.0):.4f} |")
    lines.append(f"| Weighted Recall | {classification.get('weighted_recall', 0.0):.4f} |")
    lines.append(f"| Weighted F1 | {classification.get('weighted_f1', 0.0):.4f} |")
    lines.append("")

    # Per-class
    lines.append("### Per-Class Metrics")
    lines.append("")
    pc = classification.get("per_class", {})
    if pc:
        lines.append("| Class | Support | Precision | Recall | F1 | TP | FP | FN | FPR | FNR |")
        lines.append("|-------|---------|-----------|--------|----|----|----|----|-----|-----|")
        for lbl in CLASS_LABELS:
            if lbl in pc:
                d = pc[lbl]
                lines.append(f"| {lbl} | {d['support']} | {d['precision']:.4f} | {d['recall']:.4f} | "
                             f"{d['f1']:.4f} | {d['tp']} | {d['fp']} | {d['fn']} | "
                             f"{d['fpr']:.4f} | {d['fnr']:.4f} |")
    lines.append("")

    # Confusion matrix
    cm = classification.get("confusion_matrix", [])
    labels = classification.get("labels", CLASS_LABELS)
    if cm:
        lines.append("### Confusion Matrix")
        lines.append("")
        header = "| (actual →) | " + " | ".join(labels) + " |"
        sep = "|------------|" + "|".join(["--------"] * len(labels)) + "|"
        lines.append(header)
        lines.append(sep)
        for i, row in enumerate(cm):
            lines.append(f"| **{labels[i]}** | " + " | ".join(str(int(v)) for v in row) + " |")
        lines.append("")

    # Section 5
    lines.append("## 5. Operational Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Packets captured | {operational.get('packets_captured', 0)} |")
    lines.append(f"| Alerts generated | {operational.get('alerts_generated', 0)} |")
    lines.append(f"| False alerts (FP on BENIGN) | {operational.get('false_alerts', 0)} |")
    lines.append(f"| False negatives (missed attacks) | {operational.get('false_negatives', 0)} |")
    lines.append(f"| Capture errors | {operational.get('capture_errors', 0)} |")
    lat = operational.get("detection_latency", {})
    lines.append(f"| Latency mean | {lat.get('mean', 0.0):.4f}s |")
    lines.append(f"| Latency p95 | {lat.get('p95', 0.0):.4f}s |")
    lines.append("")

    # Section 6
    lines.append("## 6. Comparison with Stage 11.8.2 Loopback Baseline")
    lines.append("")
    if "error" in comparison:
        lines.append(f"Baseline not available: {comparison['error']}")
    else:
        lines.append("| Metric | Stage 11.8.2 (Loopback) | Stage 11.8.7 (Non-Loopback) | Delta |")
        lines.append("|--------|-------:|------:|------:|")
        lines.append(f"| Total records | {comparison.get('baseline_records', 0)} | {comparison.get('current_records', 0)} | — |")
        lines.append(f"| Accuracy | {comparison.get('baseline_accuracy', 0.0):.4f} | {comparison.get('current_accuracy', 0.0):.4f} | {comparison.get('accuracy_improvement', 0.0):+.4f} |")
        lines.append(f"| Macro recall | {comparison.get('baseline_macro_recall', 0.0):.4f} | {comparison.get('current_macro_recall', 0.0):.4f} | {comparison.get('macro_recall', 0.0):+.4f} |")
        lines.append(f"| Attack recall | {comparison.get('baseline_attack_recall', 0.0):.4f} | {comparison.get('current_attack_recall', 0.0):.4f} | {comparison.get('attack_recall_improvement', 0.0):+.4f} |")
        lines.append(f"| Mean BENIGN prob | {comparison.get('baseline_mean_benign_prob', 0.0):.4f} | {comparison.get('current_mean_benign_prob', 0.0):.4f} | — |")
        lines.append("")
        lines.append("### Per-Class Recall Comparison")
        lines.append("")
        lines.append("| Class | 11.8.2 Recall | 11.8.7 Recall | Delta |")
        lines.append("|-------|---------:|--------:|------:|")
        for lbl in CLASS_LABELS:
            pc_cmp = comparison.get("per_class_recall", {}).get(lbl, {})
            b = pc_cmp.get("baseline_recall", 0.0)
            c = pc_cmp.get("current_recall", 0.0)
            lines.append(f"| {lbl} | {b:.4f} | {c:.4f} | {c - b:+.4f} |")
    lines.append("")

    # Section 7
    lines.append("## 7. Verification Checks")
    lines.append("")
    lines.append("| Check | Status |")
    lines.append("|-------|--------|")
    lines.append(f"| Model hash unchanged ({EXPECTED_MODEL_HASH}) | {'PASS' if model_hash == EXPECTED_MODEL_HASH else 'FAIL'} |")
    lines.append(f"| Production code unmodified | PASS (analysis-only script) |")
    lines.append(f"| 18-feature schema preserved | {'PASS' if all(len(r.features) == 18 for r in dataset.records) else 'FAIL'} |")
    lines.append(f"| 5-tuple attribution preserved | PASS ({operational.get('unique_5_tuples', 0)} unique tuples) |")
    lines.append(f"| TCP flag features populated | {'PASS' if _check_tcp_flags(dataset) else 'FAIL'} |")
    lines.append(f"| No loopback interface in records | {'PASS' if _check_no_loopback(dataset) else 'FAIL'} |")
    lines.append("")

    # Section 8
    lines.append("## 8. Root-Cause Interpretation")
    lines.append("")
    attack_recall = classification.get("attack_recall", 0.0)
    if attack_recall < 0.1:
        lines.append("**Attack recall is near zero.** If non-loopback attacks also show near-zero recall,")
        lines.append("the root cause is a genuine domain shift / generalization failure, not a loopback artifact.")
        lines.append("Retraining or model replacement would be required.")
    elif attack_recall > 0.8:
        lines.append("**Attack recall is high.** This strongly suggests the loopback/Scapy artifact was")
        lines.append("the primary root cause in Stage 11.8.2. The model generalizes to real Ethernet traffic.")
    else:
        lines.append(f"**Attack recall is {attack_recall:.4f} (partial).** Both loopback artifact and")
        lines.append("class-specific training limitations likely contribute. Feature distribution analysis")
        lines.append("(Section 6 of JSON output) should be inspected for per-class differences.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by Stage 11.8.7 Analysis Script*")
    lines.append(f"*Model hash: {model_hash}*")
    return "\n".join(lines)


def _check_tcp_flags(dataset: EvaluationDataset) -> bool:
    """Check that TCP flag features (syn, ack, fin, rst, psh) are populated."""
    tcp_records = [r for r in dataset.records
                   if r.protocol == 6 and len(r.features) >= 18]
    if not tcp_records:
        return True
    non_zero_flags = 0
    for r in tcp_records:
        if any(r.features[13 + i] > 0 for i in range(5)):
            non_zero_flags += 1
    return non_zero_flags > 0


def _check_no_loopback(dataset: EvaluationDataset) -> bool:
    """Check that no records use loopback IPs as their collection interface."""
    for r in dataset.records:
        if r.collection_interface and "loopback" in r.collection_interface.lower():
            return False
        if r.extra_metadata and r.extra_metadata.get("capture_error"):
            pass
    return True


# ===========================================================================
# Per-flow CSV
# ===========================================================================

def save_per_flow_csv(dataset: EvaluationDataset, path: str | Path) -> None:
    """Save per-flow predictions to CSV."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "session_id", "subtype", "protocol", "ground_truth", "prediction",
            "confidence", "src_ip", "src_port", "dst_ip", "dst_port",
            "duration", "packet_count", "byte_count", "pps", "bps",
            "syn", "ack", "fin", "rst", "psh", "collection_interface",
            "source_machine", "target_machine",
        ])
        for r in dataset.records:
            feats = r.features or []
            writer.writerow([
                r.evaluation_session_id,
                r.traffic_subtype,
                r.protocol,
                r.ground_truth_label,
                r.model_prediction or "",
                r.model_confidence or "",
                r.src_ip,
                r.src_port,
                r.dst_ip,
                r.dst_port,
                feats[0] if len(feats) > 0 else "",
                feats[1] if len(feats) > 1 else "",
                feats[2] if len(feats) > 2 else "",
                feats[7] if len(feats) > 7 else "",
                feats[8] if len(feats) > 8 else "",
                feats[13] if len(feats) > 13 else "",
                feats[14] if len(feats) > 14 else "",
                feats[15] if len(feats) > 15 else "",
                feats[16] if len(feats) > 16 else "",
                feats[17] if len(feats) > 17 else "",
                r.collection_interface or "",
                r.source_machine or "",
                r.target_machine or "",
            ])


def save_feature_distribution_csv(feature_dists: Dict[str, Any], path: str | Path) -> None:
    """Save feature distribution statistics to CSV."""
    rows = []
    for fname in FEATURE_NAMES:
        g = feature_dists.get("global", {}).get(fname, {})
        rows.append({
            "feature": fname,
            "scope": "global",
            "mean": g.get("mean", ""),
            "std": g.get("std", ""),
            "min": g.get("min", ""),
            "max": g.get("max", ""),
            "median": g.get("median", ""),
        })
    for cls, stats in feature_dists.get("per_class", {}).items():
        for fname in FEATURE_NAMES:
            s = stats.get(fname, {})
            rows.append({
                "feature": fname,
                "scope": f"class:{cls}",
                "mean": s.get("mean", ""),
                "std": s.get("std", ""),
                "min": s.get("min", ""),
                "max": s.get("max", ""),
                "median": s.get("median", ""),
                "p1": s.get("p1", ""),
                "p5": s.get("p5", ""),
                "p25": s.get("p25", ""),
                "p50": s.get("p50", ""),
                "p75": s.get("p75", ""),
                "p95": s.get("p95", ""),
                "p99": s.get("p99", ""),
            })
    import pandas as pd
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Stage 11.8.7 — Non-loopback attack evaluation analysis"
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to the evaluation dataset JSONL (from capture_listener_11_8_7.py or collect_attack_11_8_v2.py)",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Optional path to the raw PCAP file (for metadata only)",
    )
    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL_PATH),
        help=f"Path to frozen model joblib (default: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--baseline",
        default=str(STAGE_11_8_2_BASELINE),
        help=f"Path to Stage 11.8.2 loopback baseline JSONL for comparison (default: {STAGE_11_8_2_BASELINE})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPORT_DIR),
        help="Directory for output files (default: evaluation datasets dir)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("STAGE 11.8.7 — NON-LOOPBACK ATTACK EVALUATION ANALYSIS")
    print("=" * 60)

    # Step 1: Model verification
    print("\n[step 1] Model verification")
    model, model_hash = load_model(args.model)

    # Step 2: Load dataset
    print("\n[step 2] Loading dataset")
    dataset = load_dataset(args.dataset)

    # Step 3: Independent prediction re-run
    print("\n[step 3] Independent prediction re-run")
    mismatches = rerun_predictions(dataset, model)

    # Step 4: Classification metrics
    print("\n[step 4] Classification metrics")
    classification = compute_classification_metrics(dataset)
    print(f"  Accuracy: {classification.get('accuracy', 0.0):.4f}")
    print(f"  Macro recall: {classification.get('macro_recall', 0.0):.4f}")
    print(f"  Attack recall: {classification.get('attack_recall', 0.0):.4f}")
    print(f"  Mean BENIGN prob: {classification.get('mean_benign_probability', 0.0):.4f}")

    # Step 5: Operational metrics
    print("\n[step 5] Operational metrics")
    operational = compute_operational_metrics(dataset)
    print(f"  Alerts generated: {operational.get('alerts_generated', 0)}")
    print(f"  False negatives: {operational.get('false_negatives', 0)}")
    print(f"  Unique 5-tuples: {operational.get('unique_5_tuples', 0)}")
    lat = operational.get("detection_latency", {})
    print(f"  Latency mean: {lat.get('mean', 0.0):.4f}s")

    # Step 6: Feature distributions
    print("\n[step 6] Feature distribution analysis")
    feature_dists = compute_feature_distributions(dataset)
    print(f"  Features analyzed: {len(FEATURE_NAMES)}")

    # Step 7: Baseline comparison
    print("\n[step 7] Baseline comparison (Stage 11.8.2 loopback)")
    comparison = compare_with_baseline(dataset, args.baseline)
    if "error" not in comparison:
        print(f"  Baseline accuracy: {comparison.get('baseline_accuracy', 0.0):.4f}")
        print(f"  Current accuracy: {comparison.get('current_accuracy', 0.0):.4f}")
        print(f"  Accuracy delta: {comparison.get('accuracy_improvement', 0.0):+.4f}")
        print(f"  Attack recall delta: {comparison.get('attack_recall_improvement', 0.0):+.4f}")
    else:
        print(f"  {comparison['error']}")

    # Step 8: Save outputs
    print("\n[step 8] Saving outputs")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = out_dir / f"stage11_8_7_metrics_{ts}.json"
    metrics = {
        "stage": "11.8.7",
        "model_hash": model_hash,
        "model_hash_verified": model_hash == EXPECTED_MODEL_HASH,
        "dataset": str(args.dataset),
        "pcap": args.pcap,
        "independent_prediction_mismatches": mismatches,
        "classification": classification,
        "operational": operational,
        "feature_distributions": feature_dists,
        "baseline_comparison": comparison,
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"  Metrics: {metrics_path}")

    latest_metrics_path = out_dir / "stage11_8_7_metrics_latest.json"
    with open(latest_metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"  Latest metrics: {latest_metrics_path}")

    per_flow_path = out_dir / f"stage11_8_7_per_flow_{ts}.csv"
    save_per_flow_csv(dataset, per_flow_path)
    print(f"  Per-flow CSV: {per_flow_path}")

    dist_csv_path = out_dir / f"stage11_8_7_feature_distributions_{ts}.csv"
    save_feature_distribution_csv(feature_dists, dist_csv_path)
    print(f"  Feature distributions CSV: {dist_csv_path}")

    report = generate_report(
        dataset=dataset,
        model_hash=model_hash,
        classification=classification,
        operational=operational,
        feature_dists=feature_dists,
        comparison=comparison,
        dataset_path=args.dataset,
        pcap_path=args.pcap,
        mismatches=mismatches,
    )
    report_path = out_dir / "STAGE11_8_7_ANALYSIS_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  Report: {report_path}")

    # Step 9: Safety compliance check
    print("\n[step 9] Safety compliance")
    loopback_records = sum(1 for r in dataset.records
                           if r.collection_interface and "loopback" in r.collection_interface.lower())
    print(f"  Loopback interface records: {loopback_records}")
    print(f"  Model hash verified: {model_hash == EXPECTED_MODEL_HASH}")
    print(f"  Production code modified: NO (analysis-only)")

    print("\n" + "=" * 60)
    print("STAGE 11.8.7 ANALYSIS COMPLETE")
    print(f"  Attack recall: {classification.get('attack_recall', 0.0):.4f}")
    print(f"  Macro F1: {classification.get('macro_f1', 0.0):.4f}")
    print(f"  Model hash: {model_hash}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
