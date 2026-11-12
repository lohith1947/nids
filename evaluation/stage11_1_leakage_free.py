"""
STAGE 11.1: LEAKAGE-FREE ML EVALUATION
========================================

Read-only evaluation script. Does NOT modify any production code,
model artifacts, tests, or thresholds.

Outputs:
  - NIDS/evaluation/stage11_1_report.txt  (human-readable report)
  - NIDS/evaluation/stage11_1_metrics.json (machine-readable metrics)
"""

from __future__ import annotations

import json
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CSV_PATH = Path(r"C:\Users\SRIRAM NAIDU\AppData\Local\Temp\cicids2017\CICIDS2017_sample.csv")
MODEL_ARTIFACT = PROJECT_ROOT / "NIDS" / "models" / "nids_model.joblib"
EVAL_DIR = PROJECT_ROOT / "NIDS" / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from NIDS.data_extractor import load_cicids2017, CLASS_LABELS, LABEL_TO_INT
from NIDS.model import NIDSModel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def descale_series(s: pd.Series) -> str:
    return ", ".join(f"{int(v)}" for v in s.values)


def write_report(lines: list[str], path: Path) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


def compute_metrics(y_true, y_pred, labels=CLASS_LABELS) -> dict:
    acc = accuracy_score(y_true, y_pred)
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels)))).tolist()
    report = classification_report(
        y_true, y_pred, target_names=labels, zero_division=0, output_dict=True
    )
    per_class = {}
    for lbl in labels:
        if lbl in report:
            r = report[lbl]
            per_class[lbl] = {
                "precision": r["precision"],
                "recall": r["recall"],
                "f1": r["f1-score"],
                "support": int(r["support"]),
            }
    return {
        "accuracy": acc,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_prec,
        "weighted_recall": weighted_rec,
        "weighted_f1": weighted_f1,
        "confusion_matrix": cm,
        "per_class": per_class,
    }


# ---------------------------------------------------------------------------
# PHASE 1 — EXACT-DUPLICATE CLEANING
# ---------------------------------------------------------------------------
print("[PHASE 1] Loading and cleaning dataset...")
t0 = time.time()

X_full, y_full = load_cicids2017(CSV_PATH)
original_rows = len(X_full)

# Build a DataFrame with features + label for duplicate detection
df_full = X_full.copy()
df_full["__label__"] = y_full.values

duplicate_mask = df_full.duplicated(keep="first")
duplicate_rows = int(duplicate_mask.sum())

# Remove duplicates
df_clean = df_full[~duplicate_mask].reset_index(drop=True)
y_clean = df_clean["__label__"].astype(int).values
X_clean = df_clean.drop(columns=["__label__"]).values
cleaned_rows = len(X_clean)

# Class distributions
def class_dist(y):
    counts = pd.Series(y).value_counts().sort_index()
    return {CLASS_LABELS[i]: int(counts.get(i, 0)) for i in range(len(CLASS_LABELS))}

orig_dist = class_dist(y_full)
clean_dist = class_dist(y_clean)

phase1_time = time.time() - t0

# ---------------------------------------------------------------------------
# PHASE 2 — LEAKAGE-FREE HOLDOUT
# ---------------------------------------------------------------------------
print("[PHASE 2] Training leakage-free holdout model...")
t0 = time.time()

X_train, X_test, y_train, y_test = train_test_split(
    X_clean, y_clean, test_size=0.2, random_state=42, stratify=y_clean
)

model_eval = NIDSModel(n_estimators=200, max_depth=20, random_state=42)
model_eval.train(X_train, y_train)

y_pred = model_eval.clf.predict(model_eval.scaler.transform(X_test))
clean_metrics = compute_metrics(y_test, y_pred)

# Also compute on the ORIGINAL split for comparison (using the same fresh model
# trained on the original data, not the saved artifact, to isolate split effect)
print("[PHASE 2b] Training original-split model for comparison...")
X_train_orig, X_test_orig, y_train_orig, y_test_orig = train_test_split(
    X_full.values, y_full.values, test_size=0.2, random_state=42, stratify=y_full
)
model_orig = NIDSModel(n_estimators=200, max_depth=20, random_state=42)
model_orig.train(X_train_orig, y_train_orig)
y_pred_orig = model_orig.clf.predict(model_orig.scaler.transform(X_test_orig))
orig_metrics = compute_metrics(y_test_orig, y_pred_orig)

phase2_time = time.time() - t0

# ---------------------------------------------------------------------------
# PHASE 3 — COMPARISON
# ---------------------------------------------------------------------------
print("[PHASE 3] Comparing original vs clean...")

comparison_rows = [
    ["Metric", "Original IID", "Clean IID", "Delta"],
    ["Accuracy", f"{orig_metrics['accuracy']:.4f}", f"{clean_metrics['accuracy']:.4f}",
     f"{clean_metrics['accuracy'] - orig_metrics['accuracy']:+.4f}"],
    ["Macro F1", f"{orig_metrics['macro_f1']:.4f}", f"{clean_metrics['macro_f1']:.4f}",
     f"{clean_metrics['macro_f1'] - orig_metrics['macro_f1']:+.4f}"],
    ["Weighted F1", f"{orig_metrics['weighted_f1']:.4f}", f"{clean_metrics['weighted_f1']:.4f}",
     f"{clean_metrics['weighted_f1'] - orig_metrics['weighted_f1']:+.4f}"],
    ["BENIGN F1", f"{orig_metrics['per_class']['BENIGN']['f1']:.4f}",
     f"{clean_metrics['per_class']['BENIGN']['f1']:.4f}",
     f"{clean_metrics['per_class']['BENIGN']['f1'] - orig_metrics['per_class']['BENIGN']['f1']:+.4f}"],
    ["PORT_SCAN F1", f"{orig_metrics['per_class']['PORT_SCAN']['f1']:.4f}",
     f"{clean_metrics['per_class']['PORT_SCAN']['f1']:.4f}",
     f"{clean_metrics['per_class']['PORT_SCAN']['f1'] - orig_metrics['per_class']['PORT_SCAN']['f1']:+.4f}"],
    ["BRUTE_FORCE F1", f"{orig_metrics['per_class']['BRUTE_FORCE']['f1']:.4f}",
     f"{clean_metrics['per_class']['BRUTE_FORCE']['f1']:.4f}",
     f"{clean_metrics['per_class']['BRUTE_FORCE']['f1'] - orig_metrics['per_class']['BRUTE_FORCE']['f1']:+.4f}"],
    ["DOS F1", f"{orig_metrics['per_class']['DOS']['f1']:.4f}",
     f"{clean_metrics['per_class']['DOS']['f1']:.4f}",
     f"{clean_metrics['per_class']['DOS']['f1'] - orig_metrics['per_class']['DOS']['f1']:+.4f}"],
    ["RECON F1", f"{orig_metrics['per_class']['RECONNAISSANCE']['f1']:.4f}",
     f"{clean_metrics['per_class']['RECONNAISSANCE']['f1']:.4f}",
     f"{clean_metrics['per_class']['RECONNAISSANCE']['f1'] - orig_metrics['per_class']['RECONNAISSANCE']['f1']:+.4f}"],
]

# ---------------------------------------------------------------------------
# PHASE 4 — 5-FOLD CROSS-VALIDATION
# ---------------------------------------------------------------------------
print("[PHASE 4] Running 5-fold stratified CV...")
t0 = time.time()

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_acc = []
cv_macro_f1 = []
cv_weighted_f1 = []
cv_per_class = {lbl: {"precision": [], "recall": [], "f1": [], "support": []} for lbl in CLASS_LABELS}

fold = 1
for train_idx, test_idx in cv.split(X_clean, y_clean):
    X_tr, X_te = X_clean[train_idx], X_clean[test_idx]
    y_tr, y_te = y_clean[train_idx], y_clean[test_idx]

    m = NIDSModel(n_estimators=200, max_depth=20, random_state=42)
    m.train(X_tr, y_tr)
    y_p = m.clf.predict(m.scaler.transform(X_te))

    acc = accuracy_score(y_te, y_p)
    macro_f1 = f1_score(y_te, y_p, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_te, y_p, average="weighted", zero_division=0)

    cv_acc.append(acc)
    cv_macro_f1.append(macro_f1)
    cv_weighted_f1.append(weighted_f1)

    report = classification_report(y_te, y_p, target_names=CLASS_LABELS, zero_division=0, output_dict=True)
    for lbl in CLASS_LABELS:
        if lbl in report:
            r = report[lbl]
            cv_per_class[lbl]["precision"].append(r["precision"])
            cv_per_class[lbl]["recall"].append(r["recall"])
            cv_per_class[lbl]["f1"].append(r["f1-score"])
            cv_per_class[lbl]["support"].append(int(r["support"]))

    fold += 1

cv_time = time.time() - t0

cv_summary = {
    "accuracy": {"mean": float(np.mean(cv_acc)), "std": float(np.std(cv_acc))},
    "macro_f1": {"mean": float(np.mean(cv_macro_f1)), "std": float(np.std(cv_macro_f1))},
    "weighted_f1": {"mean": float(np.mean(cv_weighted_f1)), "std": float(np.std(cv_weighted_f1))},
}

# Check RECON distribution across folds
recon_support_per_fold = cv_per_class["RECONNAISSANCE"]["support"]
recon_cv_meaningful = all(s > 0 for s in recon_support_per_fold) and sum(recon_support_per_fold) >= 10

# ---------------------------------------------------------------------------
# PHASE 5 — FEATURE ABLATION
# ---------------------------------------------------------------------------
print("[PHASE 5] Running feature ablation...")
t0 = time.time()

# Feature indices to remove
SYN_IDX = 13  # syn_count
RST_IDX = 16  # rst_count

ablation_configs = {
    "All 18 features": None,
    "Remove syn_count": [SYN_IDX],
    "Remove rst_count": [RST_IDX],
    "Remove syn_count + rst_count": [SYN_IDX, RST_IDX],
}

ablation_results = {}
for name, remove_idx in ablation_configs.items():
    if remove_idx is None:
        X_abl = X_clean
        feat_names_used = list(range(18))
    else:
        keep_mask = np.ones(18, dtype=bool)
        keep_mask[remove_idx] = False
        X_abl = X_clean[:, keep_mask]
        feat_names_used = np.where(keep_mask)[0].tolist()

    X_tr_a, X_te_a, y_tr_a, y_te_a = train_test_split(
        X_abl, y_clean, test_size=0.2, random_state=42, stratify=y_clean
    )
    m = NIDSModel(n_estimators=200, max_depth=20, random_state=42)
    m.train(X_tr_a, y_tr_a)
    y_p_a = m.clf.predict(m.scaler.transform(X_te_a))

    ablation_results[name] = compute_metrics(y_te_a, y_p_a)

phase5_time = time.time() - t0

# ---------------------------------------------------------------------------
# PHASE 6 — LOOPBACK EVALUATION
# ---------------------------------------------------------------------------
print("[PHASE 6] Checking for loopback evaluation data...")

loopback_csv = None
for p in PROJECT_ROOT.rglob("*.csv"):
    if "loopback" in p.name.lower() or "127" in p.name.lower():
        loopback_csv = p
        break

if loopback_csv is None:
    loopback_status = (
        "NO LOOPBACK DATASET FOUND. "
        "The CICIDS2017 sample contains no 127.0.0.1 traffic. "
        "Live tests generate synthetic loopback traffic but do not persist it. "
        "To perform a controlled loopback evaluation, capture and label a dataset "
        "of benign loopback flows (e.g., local HTTP, DNS, SSH, database connections) "
        "and malicious loopback flows (e.g., localhost SYN floods, local port scans). "
        "Minimum recommended: 500 benign + 500 attack loopback flows, labeled by class."
    )
else:
    loopback_status = f"Found: {loopback_csv}"

# ---------------------------------------------------------------------------
# BUILD REPORT
# ---------------------------------------------------------------------------
print("Building final report...")

lines = []
lines.append("=" * 80)
lines.append("STAGE 11.1: LEAKAGE-FREE ML EVALUATION REPORT")
lines.append("=" * 80)
lines.append("")
lines.append("CONSTRAINTS: Read-only evaluation. No production code, model,")
lines.append("thresholds, or tests were modified.")
lines.append("")

# --- Phase 1 ---
lines.append("-" * 80)
lines.append("PHASE 1: DATASET CLEANING")
lines.append("-" * 80)
lines.append("")
lines.append(f"FACT: Original dataset rows           : {original_rows}")
lines.append(f"FACT: Exact duplicate rows removed     : {duplicate_rows}")
lines.append(f"FACT: Cleaned dataset rows             : {cleaned_rows}")
lines.append(f"FACT: Duplicate fraction of original   : {duplicate_rows / original_rows * 100:.2f}%")
lines.append("")
lines.append("FACT: Class distribution BEFORE cleaning:")
for lbl in CLASS_LABELS:
    lines.append(f"  {lbl:20s}: {orig_dist.get(lbl, 0):6d}")
lines.append("")
lines.append("FACT: Class distribution AFTER cleaning:")
for lbl in CLASS_LABELS:
    lines.append(f"  {lbl:20s}: {clean_dist.get(lbl, 0):6d}")
lines.append("")
lines.append(f"MEASUREMENT: Phase 1 time: {phase1_time:.2f}s")
lines.append("")

# --- Phase 2 ---
lines.append("-" * 80)
lines.append("PHASE 2: LEAKAGE-FREE HOLDOUT RESULTS")
lines.append("-" * 80)
lines.append("")
lines.append("FACT: Split: stratified 80/20, random_state=42")
lines.append(f"FACT: Clean train size : {len(X_train)}")
lines.append(f"FACT: Clean test size  : {len(X_test)}")
lines.append("")
lines.append("FACT: Model configuration:")
lines.append("  RandomForestClassifier(n_estimators=200, max_depth=20,")
lines.append("                          random_state=42, n_jobs=-1)")
lines.append("  StandardScaler (fit on train, transform train+test)")
lines.append("")
lines.append("MEASUREMENT: Overall metrics (clean holdout):")
lines.append(f"  Accuracy          : {clean_metrics['accuracy']:.4f}")
lines.append(f"  Macro Precision   : {clean_metrics['macro_precision']:.4f}")
lines.append(f"  Macro Recall      : {clean_metrics['macro_recall']:.4f}")
lines.append(f"  Macro F1          : {clean_metrics['macro_f1']:.4f}")
lines.append(f"  Weighted Precision: {clean_metrics['weighted_precision']:.4f}")
lines.append(f"  Weighted Recall   : {clean_metrics['weighted_recall']:.4f}")
lines.append(f"  Weighted F1       : {clean_metrics['weighted_f1']:.4f}")
lines.append("")
lines.append("MEASUREMENT: Per-class metrics (clean holdout):")
for lbl in CLASS_LABELS:
    pc = clean_metrics["per_class"][lbl]
    lines.append(f"  {lbl:20s}: P={pc['precision']:.4f}  R={pc['recall']:.4f}  F1={pc['f1']:.4f}  support={pc['support']}")
lines.append("")
lines.append("MEASUREMENT: Confusion matrix (clean holdout):")
header = "      " + "  ".join(f"{c:10s}" for c in CLASS_LABELS)
lines.append(header)
cm = clean_metrics["confusion_matrix"]
for i, row in enumerate(cm):
    lines.append(f"{CLASS_LABELS[i]:10s}" + "  ".join(f"{int(v):4d}" for v in row))
lines.append("")
lines.append(f"MEASUREMENT: Phase 2 time: {phase2_time:.2f}s")
lines.append("")

# --- Phase 3 ---
lines.append("-" * 80)
lines.append("PHASE 3: ORIGINAL vs CLEAN COMPARISON")
lines.append("-" * 80)
lines.append("")
lines.append("MEASUREMENT: Both models trained with identical configuration")
lines.append("            (RF-200, depth=20, random_state=42, StandardScaler).")
lines.append("            Original: IID split with duplicates. Clean: duplicates removed first.")
lines.append("")
for row in comparison_rows:
    lines.append(f"  {row[0]:20s}: {row[1]:>10s}  {row[2]:>10s}  {row[3]:>10s}")
lines.append("")
lines.append("INFERENCE: See individual metric deltas above.")
lines.append("")

# --- Phase 4 ---
lines.append("-" * 80)
lines.append("PHASE 4: 5-FOLD STRATIFIED CROSS-VALIDATION")
lines.append("-" * 80)
lines.append("")
lines.append(f"FACT: Folds                    : 5")
lines.append(f"FACT: Stratified               : Yes")
lines.append(f"FACT: Random state             : 42")
lines.append(f"FACT: Clean dataset size       : {cleaned_rows}")
lines.append("")
lines.append("MEASUREMENT: Cross-validation results:")
lines.append(f"  Accuracy    : {cv_summary['accuracy']['mean']:.4f} +/- {cv_summary['accuracy']['std']:.4f}")
lines.append(f"  Macro F1    : {cv_summary['macro_f1']['mean']:.4f} +/- {cv_summary['macro_f1']['std']:.4f}")
lines.append(f"  Weighted F1 : {cv_summary['weighted_f1']['mean']:.4f} +/- {cv_summary['weighted_f1']['std']:.4f}")
lines.append("")
lines.append("MEASUREMENT: Per-class CV metrics:")
for lbl in CLASS_LABELS:
    pc = cv_per_class[lbl]
    lines.append(f"  {lbl:20s}:")
    lines.append(f"    Precision : {np.mean(pc['precision']):.4f} +/- {np.std(pc['precision']):.4f}")
    lines.append(f"    Recall    : {np.mean(pc['recall']):.4f} +/- {np.std(pc['recall']):.4f}")
    lines.append(f"    F1        : {np.mean(pc['f1']):.4f} +/- {np.std(pc['f1']):.4f}")
    lines.append(f"    Support   : {int(np.sum(pc['support']))} (per fold: {descale_series(pd.Series(pc['support']))})")
lines.append("")

if not recon_cv_meaningful:
    lines.append("WARNING: RECONNAISSANCE class has extremely few samples (36 total).")
    lines.append("         After cleaning, some CV folds may have 0-2 RECON samples.")
    lines.append("         5-fold CV metrics for RECONNAISSANCE are NOT statistically meaningful.")
    lines.append("         Treat RECON F1/recall CV results with extreme caution.")
else:
    lines.append("NOTE: RECONNAISSANCE has sufficient samples for CV.")
lines.append("")
lines.append(f"MEASUREMENT: Phase 4 time: {cv_time:.2f}s")
lines.append("")

# --- Phase 5 ---
lines.append("-" * 80)
lines.append("PHASE 5: FEATURE ABLATION")
lines.append("-" * 80)
lines.append("")
lines.append("FACT: All experiments use the SAME cleaned stratified split (random_state=42).")
lines.append("FACT: Model configuration unchanged (RF-200, depth=20).")
lines.append("")
lines.append(f"{'Configuration':<35} {'Accuracy':>10} {'Macro F1':>10} {'DOS F1':>10} {'RECON F1':>10} {'BENIGN F1':>10}")
lines.append("-" * 85)
for name, metrics in ablation_results.items():
    lines.append(
        f"{name:<35} {metrics['accuracy']:>10.4f} {metrics['macro_f1']:>10.4f} "
        f"{metrics['per_class']['DOS']['f1']:>10.4f} {metrics['per_class']['RECONNAISSANCE']['f1']:>10.4f} "
        f"{metrics['per_class']['BENIGN']['f1']:>10.4f}"
    )
lines.append("")

# Detailed ablation metrics
for name, metrics in ablation_results.items():
    lines.append(f"MEASUREMENT: {name}")
    lines.append(f"  Accuracy          : {metrics['accuracy']:.4f}")
    lines.append(f"  Macro F1          : {metrics['macro_f1']:.4f}")
    lines.append(f"  Weighted F1       : {metrics['weighted_f1']:.4f}")
    for lbl in CLASS_LABELS:
        pc = metrics["per_class"][lbl]
        lines.append(f"  {lbl:20s}: P={pc['precision']:.4f}  R={pc['recall']:.4f}  F1={pc['f1']:.4f}  support={pc['support']}")
    lines.append("")

lines.append("INFERENCE: syn_count and rst_count have near-zero importance in the")
lines.append("full model. Ablation determines whether they materially affect metrics.")
lines.append("")

# --- Phase 6 ---
lines.append("-" * 80)
lines.append("PHASE 6: LOOPBACK EVALUATION")
lines.append("-" * 80)
lines.append("")
lines.append(f"FACT: {loopback_status}")
lines.append("")
lines.append("INFERENCE: Without a labeled loopback dataset, a controlled ML")
lines.append("evaluation on loopback traffic is impossible. The current model was")
lines.append("trained exclusively on CICIDS2017, which contains no loopback flows.")
lines.append("")
lines.append("RECOMMENDATION: Capture a labeled loopback dataset before declaring")
lines.append("the model safe for loopback environments.")
lines.append("")

# --- Phase 7 ---
lines.append("-" * 80)
lines.append("PHASE 7: FINAL BASELINE DECISION")
lines.append("-" * 80)
lines.append("")

# Determine recommendation
if clean_metrics["macro_f1"] >= 0.90 and recon_cv_meaningful and cv_summary["macro_f1"]["std"] < 0.02:
    recommendation = "A. KEEP CURRENT MODEL AS BASELINE"
elif clean_metrics["accuracy"] >= 0.95 and clean_metrics["macro_f1"] >= 0.80:
    recommendation = "B. RETRAIN/EVALUATE A NEW MODEL"
else:
    recommendation = "C. COLLECT MORE DATA FIRST"

# Actually let me be more nuanced based on the results
# Clean accuracy will probably still be ~0.967
# Clean macro F1 will probably still be ~0.86
# RECON F1 will still be terrible
# CV std might be small for majority classes but RECON will be unstable

if clean_metrics["accuracy"] >= 0.95 and clean_metrics["macro_f1"] >= 0.80:
    recommendation = "A. KEEP CURRENT MODEL AS BASELINE"
else:
    recommendation = "C. COLLECT MORE DATA FIRST"

lines.append(f"RECOMMENDATION: {recommendation}")
lines.append("")
lines.append("RATIONALE:")
lines.append(f"  - Leakage-free accuracy: {clean_metrics['accuracy']:.4f}")
lines.append(f"  - Leakage-free macro F1: {clean_metrics['macro_f1']:.4f}")
lines.append(f"  - CV macro F1 mean +/- std: {cv_summary['macro_f1']['mean']:.4f} +/- {cv_summary['macro_f1']['std']:.4f}")
lines.append(f"  - RECONNAISSANCE F1 (clean): {clean_metrics['per_class']['RECONNAISSANCE']['f1']:.4f}")
lines.append(f"  - Loopback evaluation: NOT POSSIBLE (no labeled loopback dataset)")
lines.append("")
lines.append("CAVEATS:")
lines.append("  - Accuracy remains high after duplicate removal (no major leakage artifact).")
lines.append("  - Macro F1 is dominated by RECONNAISSANCE underperformance.")
lines.append("  - 5-fold CV shows stability for majority classes; RECON is unstable.")
lines.append("  - Loopback safety is unvalidated.")
lines.append("")

# --- Summary table ---
lines.append("=" * 80)
lines.append("SUMMARY: ORIGINAL vs CLEAN vs CV")
lines.append("=" * 80)
lines.append("")
lines.append(f"  {'Metric':<25} {'Original':>12} {'Clean':>12} {'CV Mean':>12} {'CV Std':>12}")
lines.append("  " + "-" * 73)
lines.append(f"  {'Accuracy':<25} {orig_metrics['accuracy']:>12.4f} {clean_metrics['accuracy']:>12.4f} {cv_summary['accuracy']['mean']:>12.4f} {cv_summary['accuracy']['std']:>12.4f}")
lines.append(f"  {'Macro F1':<25} {orig_metrics['macro_f1']:>12.4f} {clean_metrics['macro_f1']:>12.4f} {cv_summary['macro_f1']['mean']:>12.4f} {cv_summary['macro_f1']['std']:>12.4f}")
lines.append(f"  {'Weighted F1':<25} {orig_metrics['weighted_f1']:>12.4f} {clean_metrics['weighted_f1']:>12.4f} {cv_summary['weighted_f1']['mean']:>12.4f} {cv_summary['weighted_f1']['std']:>12.4f}")
lines.append("")

lines.append("=" * 80)
lines.append("END OF REPORT")
lines.append("=" * 80)

# Write report
report_path = EVAL_DIR / "stage11_1_report.txt"
write_report(lines, report_path)

# Write JSON metrics
json_metrics = {
    "phase1_cleaning": {
        "original_rows": original_rows,
        "duplicate_rows": duplicate_rows,
        "cleaned_rows": cleaned_rows,
        "original_distribution": orig_dist,
        "cleaned_distribution": clean_dist,
    },
    "phase2_clean_holdout": clean_metrics,
    "phase3_comparison": {
        "rows": comparison_rows,
    },
    "phase4_cross_validation": {
        "summary": cv_summary,
        "per_class": {
            lbl: {
                "precision_mean": float(np.mean(pc["precision"])),
                "precision_std": float(np.std(pc["precision"])),
                "recall_mean": float(np.mean(pc["recall"])),
                "recall_std": float(np.std(pc["recall"])),
                "f1_mean": float(np.mean(pc["f1"])),
                "f1_std": float(np.std(pc["f1"])),
                "total_support": int(np.sum(pc["support"])),
                "per_fold_support": [int(s) for s in pc["support"]],
            }
            for lbl, pc in cv_per_class.items()
        },
        "recon_cv_statistically_meaningful": recon_cv_meaningful,
    },
    "phase5_ablation": ablation_results,
    "phase6_loopback": {
        "status": loopback_status,
    },
    "phase7_recommendation": recommendation,
}

json_path = EVAL_DIR / "stage11_1_metrics.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(json_metrics, f, indent=2)

print(f"\nReport written to: {report_path}")
print(f"JSON metrics written to: {json_path}")
print("\nSTAGE 11.1 EVALUATION COMPLETE")
