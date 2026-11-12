"""
Stage 11.8.6 — Feature-Space Deep Dive Analysis
Evaluation-only diagnostic script. Does not modify model, thresholds, or production code.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp, wasserstein_distance
from sklearn.metrics import roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.data_extractor import CLASS_LABELS, extract_features, load_cicids2017
from NIDS.features import NUMERIC_FEATURE_NAMES

# Paths
CICIDS_CSV = Path(r"C:\Users\SRIRAM NAIDU\AppData\Local\Temp\cicids2017\CICIDS2017_sample.csv")
ATTACK_JSONL = Path("NIDS/evaluation/datasets/attack_11_8_2_20260910T140310Z.jsonl")
BENIGN_JSONL = Path("NIDS/evaluation/datasets/expanded_11_7_20260910T081352Z.jsonl")
MODEL_PATH = Path("NIDS/models/nids_model.joblib")
OUT_DIR = Path("NIDS/evaluation/datasets")
OUT_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_NAMES = NUMERIC_FEATURE_NAMES


def load_model():
    bundle = joblib.load(str(MODEL_PATH))
    return bundle["scaler"], bundle["clf"]


def compute_model_hash() -> str:
    data = open(str(MODEL_PATH), "rb").read()
    return hashlib.sha256(data).hexdigest()[:16]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def extract_live_features(records: List[Dict[str, Any]]) -> np.ndarray:
    return np.array([r["features"] for r in records], dtype=np.float64)


def percentile(a: np.ndarray, p: float) -> float:
    return float(np.percentile(a, p))


def compute_stats(arr: np.ndarray) -> Dict[str, float]:
    arr = arr[~np.isnan(arr)]
    if len(arr) == 0:
        return {k: 0.0 for k in ["count", "mean", "median", "std", "min", "max", "P1", "P5", "P25", "P50", "P75", "P95", "P99"]}
    return {
        "count": int(len(arr)),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "P1": percentile(arr, 1),
        "P5": percentile(arr, 5),
        "P25": percentile(arr, 25),
        "P50": percentile(arr, 50),
        "P75": percentile(arr, 75),
        "P95": percentile(arr, 95),
        "P99": percentile(arr, 99),
    }


def run_predictions(scaler, clf, X: np.ndarray) -> Dict[str, Any]:
    X_scaled = scaler.transform(X)
    probs = clf.predict_proba(X_scaled)
    preds = clf.predict(X_scaled)
    pred_indices = np.clip(preds, 0, len(CLASS_LABELS) - 1)
    pred_labels = [CLASS_LABELS[i] for i in pred_indices]
    confidences = [float(probs[i, pred_indices[i]]) for i in range(len(pred_indices))]

    top3 = []
    margins = []
    benign_probs = []
    for i in range(len(X)):
        p = probs[i]
        sorted_idx = np.argsort(p)[::-1]
        top3.append([CLASS_LABELS[j] for j in sorted_idx[:3]])
        margins.append(float(p[sorted_idx[0]] - p[sorted_idx[1]]))
        benign_probs.append(float(p[CLASS_LABELS.index("BENIGN")]))
    return {
        "pred_labels": pred_labels,
        "confidences": confidences,
        "top3": top3,
        "margins": margins,
        "benign_probs": benign_probs,
        "probs": probs,
    }


def main():
    print("[stage11.8.6] Starting feature-space deep dive...")

    # Step 1: Verify model
    scaler, clf = load_model()
    model_hash = compute_model_hash()
    print(f"[model] class={type(clf).__name__}, n_estimators={clf.n_estimators}, max_depth={clf.max_depth}, random_state={clf.random_state}, n_jobs={clf.n_jobs}, n_features_in_={clf.n_features_in_}, classes_={clf.classes_}")
    print(f"[model] hash={model_hash}")

    # Step 2: Load datasets
    print("[data] Loading CICIDS2017...")
    cicids_features, cicids_labels = load_cicids2017(CICIDS_CSV)
    cicids_X = cicids_features.values.astype(np.float64)
    cicids_y_int = cicids_labels.values.astype(int)
    cicids_y_str = [CLASS_LABELS[i] for i in cicids_y_int]

    print("[data] Loading live attack JSONL...")
    attack_records = load_jsonl(ATTACK_JSONL)
    attack_X = extract_live_features(attack_records)
    attack_y_str = [r["ground_truth_label"] for r in attack_records]

    print("[data] Loading live benign JSONL...")
    benign_records = load_jsonl(BENIGN_JSONL)
    benign_X = extract_live_features(benign_records)
    benign_y_str = ["BENIGN"] * len(benign_records)

    print(f"[data] CICIDS shape: {cicids_X.shape}")
    print(f"[data] Attack shape: {attack_X.shape}")
    print(f"[data] Benign shape: {benign_X.shape}")

    # Step 3-4: Class-conditioned CICIDS baselines
    print("[baseline] Computing CICIDS class-conditioned statistics...")
    cicids_baselines: Dict[str, Dict[str, Dict[str, float]]] = {}
    for cls in CLASS_LABELS:
        mask = np.array([y == cls for y in cicids_y_str])
        if mask.sum() == 0:
            continue
        cls_stats = {}
        for idx, feat in enumerate(FEATURE_NAMES):
            cls_stats[feat] = compute_stats(cicids_X[mask, idx])
        cicids_baselines[cls] = cls_stats

    # Step 5: Live attack/benign distributions
    print("[live] Computing live distributions...")
    live_dist: Dict[str, Dict[str, Dict[str, float]]] = {}
    for cls in ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]:
        if cls == "BENIGN":
            X = benign_X
        else:
            mask = np.array([y == cls for y in attack_y_str])
            X = attack_X[mask]
        if len(X) == 0:
            continue
        cls_stats = {}
        for idx, feat in enumerate(FEATURE_NAMES):
            cls_stats[feat] = compute_stats(X[:, idx])
        live_dist[cls] = cls_stats

    # Step 6: Feature shift matrix
    print("[shift] Building feature shift matrix...")
    shift_rows = []
    attack_classes = ["PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]
    for feat in FEATURE_NAMES[:13]:
        for cls in attack_classes:
            if cls not in cicids_baselines or cls not in live_dist:
                continue
            c_med = cicids_baselines[cls][feat]["median"]
            l_med = live_dist[cls][feat]["median"]
            ratio = l_med / c_med if c_med != 0 else float("inf")
            shift_rows.append({
                "feature": feat,
                "attack_class": cls,
                "cicids_attack_median": c_med,
                "live_attack_median": l_med,
                "ratio": ratio,
                "cicids_P99": cicids_baselines[cls][feat]["P99"],
                "live_P95": live_dist[cls][feat]["P95"],
            })
    shift_df = pd.DataFrame(shift_rows)
    shift_df.to_csv(OUT_DIR / "stage11_8_6_distribution_shift.csv", index=False)

    # Step 7: Statistical distribution distances
    print("[stats] Computing distribution distances...")
    stat_rows = []
    # CICIDS BENIGN vs live attacks
    for cls in attack_classes:
        if cls not in live_dist or "BENIGN" not in cicids_baselines:
            continue
        for feat in FEATURE_NAMES:
            c_ben = cicids_baselines["BENIGN"][feat]
            l_cls = live_dist[cls][feat]
            c_ben_arr = cicids_X[np.array([y == "BENIGN" for y in cicids_y_str]), FEATURE_NAMES.index(feat)]
            l_arr = attack_X[np.array([y == cls for y in attack_y_str]), FEATURE_NAMES.index(feat)]
            if len(c_ben_arr) == 0 or len(l_arr) == 0:
                continue
            try:
                wd = wasserstein_distance(c_ben_arr, l_arr)
                ks_stat, ks_p = ks_2samp(c_ben_arr, l_arr)
            except Exception:
                wd = float("nan")
                ks_stat = float("nan")
                ks_p = float("nan")
            stat_rows.append({
                "comparison": "CICIDS_BENIGN_vs_live_" + cls,
                "feature": feat,
                "wasserstein": wd,
                "ks_stat": ks_stat,
                "ks_pvalue": ks_p,
            })
    # CICIDS corresponding attack class vs live attack
    for cls in attack_classes:
        if cls not in cicids_baselines or cls not in live_dist:
            continue
        c_arr = cicids_X[np.array([y == cls for y in cicids_y_str]), FEATURE_NAMES.index(feat)]
        l_arr = attack_X[np.array([y == cls for y in attack_y_str]), FEATURE_NAMES.index(feat)]
        if len(c_arr) == 0 or len(l_arr) == 0:
            continue
        for feat in FEATURE_NAMES:
            c_cls_arr = cicids_X[np.array([y == cls for y in cicids_y_str]), FEATURE_NAMES.index(feat)]
            l_cls_arr = attack_X[np.array([y == cls for y in attack_y_str]), FEATURE_NAMES.index(feat)]
            if len(c_cls_arr) == 0 or len(l_cls_arr) == 0:
                continue
            try:
                wd = wasserstein_distance(c_cls_arr, l_cls_arr)
                ks_stat, ks_p = ks_2samp(c_cls_arr, l_cls_arr)
            except Exception:
                wd = float("nan")
                ks_stat = float("nan")
                ks_p = float("nan")
            stat_rows.append({
                "comparison": f"CICIDS_{cls}_vs_live_{cls}",
                "feature": feat,
                "wasserstein": wd,
                "ks_stat": ks_stat,
                "ks_pvalue": ks_p,
            })
    stat_df = pd.DataFrame(stat_rows)
    stat_df.to_csv(OUT_DIR / "stage11_8_6_distribution_distances.csv", index=False)

    # Step 8: Range overlap
    print("[overlap] Computing range overlap...")
    overlap_rows = []
    for cls in attack_classes:
        if cls not in cicids_baselines or cls not in live_dist:
            continue
        mask = np.array([y == cls for y in attack_y_str])
        l_arr = attack_X[mask]
        if len(l_arr) == 0:
            continue
        for feat in FEATURE_NAMES[:13]:
            idx = FEATURE_NAMES.index(feat)
            c_p5 = cicids_baselines[cls][feat]["P5"]
            c_p95 = cicids_baselines[cls][feat]["P95"]
            c_min = cicids_baselines[cls][feat]["min"]
            c_max = cicids_baselines[cls][feat]["max"]
            c_p99 = cicids_baselines[cls][feat]["P99"]
            c_p1 = cicids_baselines[cls][feat]["P1"]
            vals = l_arr[:, idx]
            inside_p5_p95 = float(np.mean((vals >= c_p5) & (vals <= c_p95)))
            inside_min_max = float(np.mean((vals >= c_min) & (vals <= c_max)))
            above_p99 = float(np.mean(vals > c_p99))
            below_p1 = float(np.mean(vals < c_p1))
            overlap_rows.append({
                "feature": feat,
                "attack_class": cls,
                "inside_p5_p95": inside_p5_p95,
                "inside_min_max": inside_min_max,
                "above_p99": above_p99,
                "below_p1": below_p1,
            })
    overlap_df = pd.DataFrame(overlap_rows)
    overlap_df.to_csv(OUT_DIR / "stage11_8_6_range_overlap.csv", index=False)

    # Step 9: BENIGN vs attack separability
    print("[separability] Computing BENIGN vs attack separability...")
    sep_rows = []
    for cls in attack_classes:
        if cls not in cicids_baselines or cls not in live_dist:
            continue
        for feat in FEATURE_NAMES[:13]:
            idx = FEATURE_NAMES.index(feat)
            c_ben = cicids_X[np.array([y == "BENIGN" for y in cicids_y_str]), idx]
            c_cls = cicids_X[np.array([y == cls for y in cicids_y_str]), idx]
            l_cls = attack_X[np.array([y == cls for y in attack_y_str]), idx]
            if len(c_ben) == 0 or len(c_cls) == 0 or len(l_cls) == 0:
                continue
            sep_rows.append({
                "feature": feat,
                "attack_class": cls,
                "cicids_benign_median": float(np.median(c_ben)),
                "cicids_attack_median": float(np.median(c_cls)),
                "live_attack_median": float(np.median(l_cls)),
                "live_vs_benign_direction": "toward_benign" if abs(float(np.median(l_cls)) - float(np.median(c_ben))) < abs(float(np.median(l_cls)) - float(np.median(c_cls))) else "away_from_benign",
            })
    sep_df = pd.DataFrame(sep_rows)
    sep_df.to_csv(OUT_DIR / "stage11_8_6_separability.csv", index=False)

    # Step 10: Model prediction analysis
    print("[prediction] Running model predictions...")
    pred_results = run_predictions(scaler, clf, attack_X)
    pred_df = pd.DataFrame({
        "ground_truth": attack_y_str,
        "prediction": pred_results["pred_labels"],
        "benign_prob": pred_results["benign_probs"],
        "confidence": pred_results["confidences"],
        "margin": pred_results["margins"],
        "top1": [t[0] for t in pred_results["top3"]],
        "top2": [t[1] for t in pred_results["top3"]],
        "top3": [t[2] for t in pred_results["top3"]],
    })
    for i, cls in enumerate(CLASS_LABELS):
        pred_df[f"prob_{cls}"] = pred_results["probs"][:, i]
    pred_df.to_csv(OUT_DIR / "stage11_8_6_prediction_analysis.csv", index=False)

    # Correlations with BENIGN probability
    corr_rows = []
    for feat in FEATURE_NAMES:
        idx = FEATURE_NAMES.index(feat)
        vals = attack_X[:, idx]
        ben = pred_results["benign_probs"]
        if np.std(vals) == 0 or np.std(ben) == 0:
            continue
        pearson = float(np.corrcoef(vals, ben)[0, 1])
        # Spearman approximation via rank correlation
        from scipy.stats import spearmanr
        spearman, sp_p = spearmanr(vals, ben)
        corr_rows.append({
            "feature": feat,
            "pearson_with_benign_prob": pearson,
            "spearman_with_benign_prob": float(spearman),
            "spearman_pvalue": float(sp_p),
        })
    corr_df = pd.DataFrame(corr_rows)
    corr_df.to_csv(OUT_DIR / "stage11_8_6_feature_correlations.csv", index=False)

    # Step 11-12: Univariate counterfactual test
    print("[counterfactual] Running univariate counterfactual diagnostics...")
    cf_rows = []
    for cls in attack_classes:
        mask = np.array([y == cls for y in attack_y_str])
        if mask.sum() == 0:
            continue
        X_cls = attack_X[mask].copy()
        y_cls = [y for i, y in enumerate(attack_y_str) if mask[i]]

        # Original predictions
        orig_results = run_predictions(scaler, clf, X_cls)
        orig_recall = sum(1 for p, y in zip(orig_results["pred_labels"], y_cls) if p == y) / len(y_cls)
        orig_benign_prob = np.mean(orig_results["benign_probs"])

        for feat in FEATURE_NAMES[:13]:
            idx = FEATURE_NAMES.index(feat)
            if cls not in cicids_baselines:
                continue
            rep_val = cicids_baselines[cls][feat]["median"]
            X_cf = X_cls.copy()
            X_cf[:, idx] = rep_val
            cf_results = run_predictions(scaler, clf, X_cf)
            cf_recall = sum(1 for p, y in zip(cf_results["pred_labels"], y_cls) if p == y) / len(y_cls)
            cf_benign_prob = np.mean(cf_results["benign_probs"])
            transitions = sum(1 for po, pc in zip(orig_results["pred_labels"], cf_results["pred_labels"]) if po != pc)
            cf_rows.append({
                "attack_class": cls,
                "feature": feat,
                "original_recall": orig_recall,
                "counterfactual_recall": cf_recall,
                "recall_improvement": cf_recall - orig_recall,
                "transitions": transitions,
                "orig_benign_prob": orig_benign_prob,
                "cf_benign_prob": cf_benign_prob,
                "benign_prob_change": cf_benign_prob - orig_benign_prob,
            })
    cf_df = pd.DataFrame(cf_rows)
    cf_df.to_csv(OUT_DIR / "stage11_8_6_counterfactual_results.csv", index=False)

    # Step 13: Top feature combinations (limited)
    print("[combinations] Testing limited feature combinations...")
    # Aggregate counterfactual improvement by feature
    cf_agg = cf_df.groupby("feature").agg({
        "recall_improvement": "mean",
        "benign_prob_change": "mean",
        "transitions": "sum",
    }).reset_index()
    cf_agg = cf_agg.sort_values("recall_improvement", ascending=False)
    top_features = cf_agg.head(5)["feature"].tolist()

    combo_rows = []
    for cls in attack_classes:
        mask = np.array([y == cls for y in attack_y_str])
        if mask.sum() == 0:
            continue
        X_cls = attack_X[mask].copy()
        y_cls = [y for i, y in enumerate(attack_y_str) if mask[i]]
        orig_results = run_predictions(scaler, clf, X_cls)
        orig_recall = sum(1 for p, y in zip(orig_results["pred_labels"], y_cls) if p == y) / len(y_cls)

        for k in [1, 2, 3]:
            feats = top_features[:k]
            idxs = [FEATURE_NAMES.index(f) for f in feats]
            X_cf = X_cls.copy()
            for idx in idxs:
                if cls in cicids_baselines:
                    rep_val = cicids_baselines[cls][feat]["median"]
                    X_cf[:, idx] = rep_val
            cf_results = run_predictions(scaler, clf, X_cf)
            cf_recall = sum(1 for p, y in zip(cf_results["pred_labels"], y_cls) if p == y) / len(y_cls)
            combo_rows.append({
                "attack_class": cls,
                "top_k": k,
                "features": ",".join(feats),
                "original_recall": orig_recall,
                "counterfactual_recall": cf_recall,
                "recall_improvement": cf_recall - orig_recall,
            })
    combo_df = pd.DataFrame(combo_rows)
    combo_df.to_csv(OUT_DIR / "stage11_8_6_combinations.csv", index=False)

    # Step 14: Duplication analysis
    print("[duplication] Analyzing training duplicates...")
    dup_rows = []
    for cls in CLASS_LABELS:
        mask = np.array([y == cls for y in cicids_y_str])
        if mask.sum() == 0:
            continue
        X_cls = cicids_X[mask]
        total = len(X_cls)
        unique = len(np.unique(X_cls, axis=0))
        dup_rows.append({
            "class": cls,
            "total_rows": total,
            "unique_rows": unique,
            "duplicate_rows": total - unique,
            "unique_ratio": unique / total if total > 0 else 0.0,
        })
    dup_df = pd.DataFrame(dup_rows)
    dup_df.to_csv(OUT_DIR / "stage11_8_6_duplication.csv", index=False)

    # Step 15: Feature importance vs evidence
    print("[importance] Comparing feature importance vs evidence...")
    imp_rows = []
    importances = clf.feature_importances_
    for i, feat in enumerate(FEATURE_NAMES):
        imp_rows.append({
            "feature": feat,
            "importance": float(importances[i]),
            "shift_evidence": "high" if feat in ["packet_size_std", "average_packet_size", "maximum_packet_size", "byte_count", "backward_bytes", "packets_per_second", "bytes_per_second"] else "moderate" if feat in ["packet_count", "duration", "forward_packets", "backward_packets", "forward_bytes"] else "low",
            "cf_evidence": "pending",
        })
    imp_df = pd.DataFrame(imp_rows)
    imp_df.to_csv(OUT_DIR / "stage11_8_6_feature_importance.csv", index=False)

    print("[stage11.8.6] Analysis complete. Outputs written to", OUT_DIR)


if __name__ == "__main__":
    main()
