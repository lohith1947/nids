#!/usr/bin/env python3
"""
Retrain the NIDS ML model with combined CICIDS2017 + live lab traffic data.

This script:
1. Downloads/loads the CICIDS2017 sample dataset (labeled training data)
2. Loads the live capture dataset from the server (real Kali attack traffic)
3. Uses rule predictions from live capture as pseudo-labels for attack records
4. Combines both datasets
5. Trains a new Random Forest model
6. Evaluates and saves the model to models/nids_model.joblib

Usage:
    python retrain_model.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from urllib.request import urlretrieve

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import json
import numpy as np
import pandas as pd

from NIDS.data_extractor import (
    CLASS_LABELS, LABEL_TO_INT, extract_features, CICIDS_COLUMN_MAPPING,
    NUMERIC_FEATURE_NAMES
)
from NIDS.model import NIDSModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATASET_URL = "https://raw.githubusercontent.com/NirmalaKTomar/CICIDS2017_Sample_dataset/main/CICIDS2017_sample.csv"
MODEL_PATH = Path(__file__).parent / "models" / "nids_model.joblib"
LIVE_DATA_PATH = Path(__file__).parent.parent / "live_test_dataset.jsonl"  # Local copy

# Rule prediction → NIDS class label mapping for pseudo-labeling live data
RULE_TO_LABEL = {
    "PORT_SCAN": "PORT_SCAN",
    "BRUTE_FORCE": "BRUTE_FORCE",
    "DOS": "DOS",
    "RECONNAISSANCE": "RECONNAISSANCE",
    "BENIGN": "BENIGN",
}


def download_dataset(dest: Path) -> Path:
    """Download the CICIDS2017 sample CSV if it does not already exist."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"[retrain] Dataset already exists at {dest} ({dest.stat().st_size / 1024:.0f} KB)")
        return dest

    print(f"[retrain] Downloading CICIDS2017 sample from GitHub...")
    print(f"[retrain]   URL: {DATASET_URL}")

    def _progress(block_num, block_size, total_size):
        if total_size > 0:
            pct = (block_num * block_size) / total_size * 100
            sys.stdout.write(f"\r[retrain]   Downloading: {pct:.1f}%")
            sys.stdout.flush()

    urlretrieve(DATASET_URL, str(dest), reporthook=_progress)
    sys.stdout.write("\n")
    print(f"[retrain] Dataset saved ({dest.stat().st_size / 1024:.0f} KB)")
    return dest


def load_live_capture_data(jsonl_path: Path) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load live capture data and use rule predictions as pseudo-labels.

    Records where rule_prediction is BENIGN but we know they came from
    attack traffic (from Kali) are labeled based on the rule prediction.
    Records where rule_prediction is BENIGN and traffic is genuinely benign
    are labeled BENIGN.
    """
    records = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"[retrain] Loaded {len(records)} live capture records")

    feature_data = {}
    for feat_name in NUMERIC_FEATURE_NAMES:
        feature_data[feat_name] = []

    labels = []
    src_ips = set()

    for r in records:
        features = r.get("features", [])
        if not features or len(features) != 18:
            continue

        for i, feat_name in enumerate(NUMERIC_FEATURE_NAMES):
            feature_data[feat_name].append(features[i])

        # Use rule prediction as pseudo-label
        rule_pred = r.get("rule_prediction", "BENIGN")
        label = RULE_TO_LABEL.get(rule_pred, "BENIGN")
        labels.append(LABEL_TO_INT[label])

        src_ips.add(r.get("src_ip", "unknown"))

    features_df = pd.DataFrame(feature_data)
    labels_series = pd.Series(labels, dtype=np.int64)

    print(f"[retrain] Live capture features shape: {features_df.shape}")
    print(f"[retrain] Live capture label distribution:")
    label_counts = labels_series.value_counts().sort_index()
    for idx, count in label_counts.items():
        print(f"[retrain]   {CLASS_LABELS[idx]}: {count} ({count / len(labels_series) * 100:.1f}%)")
    print(f"[retrain] Unique source IPs: {len(src_ips)} - {sorted(src_ips)}")

    return features_df, labels_series


def combine_datasets(cicids_X, cicids_y, live_X, live_y):
    """Combine CICIDS2017 and live capture datasets."""
    # Align columns
    live_X = live_X.reindex(columns=cicids_X.columns, fill_value=0)

    X_combined = pd.concat([cicids_X, live_X], ignore_index=True)
    y_combined = pd.concat([cicids_y, live_y], ignore_index=True)

    print(f"[retrain] Combined dataset shape: {X_combined.shape}")
    print(f"[retrain] Combined label distribution:")
    label_counts = y_combined.value_counts().sort_index()
    for idx, count in label_counts.items():
        print(f"[retrain]   {CLASS_LABELS[idx]}: {count} ({count / len(y_combined) * 100:.1f}%)")

    return X_combined, y_combined


def train():
    """Main retraining pipeline."""
    np.random.seed(42)

    # 1. Load CICIDS2017 dataset
    print("\n[retrain] Phase 1: Loading CICIDS2017 dataset...")
    csv_path = download_dataset(Path(tempfile.gettempdir()) / "cicids2017" / "CICIDS2017_sample.csv")
    X_cicids, y_cicids = extract_features(pd.read_csv(csv_path))
    print(f"[retrain] CICIDS2017 features shape: {X_cicids.shape}")
    label_counts = y_cicids.value_counts().sort_index()
    for idx, count in label_counts.items():
        print(f"[retrain]   {CLASS_LABELS[idx]}: {count} ({count / len(y_cicids) * 100:.1f}%)")

    # 2. Load live capture data
    print("\n[retrain] Phase 2: Loading live capture data...")
    if LIVE_DATA_PATH.exists():
        X_live, y_live = load_live_capture_data(LIVE_DATA_PATH)
        X, y = combine_datasets(X_cicids, y_cicids, X_live, y_live)
    else:
        print(f"[retrain] WARNING: Live data not found at {LIVE_DATA_PATH}. Using CICIDS2017 only.")
        X, y = X_cicids, y_cicids

    # 3. Train/test split
    print("\n[retrain] Phase 3: Train/test split...")
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y.values, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[retrain] Train set: {X_train.shape[0]} samples")
    print(f"[retrain] Test set:  {X_test.shape[0]} samples")

    # 4. Train model
    print("\n[retrain] Phase 4: Training Random Forest model...")
    model = NIDSModel(
        n_estimators=300,
        max_depth=25,
        random_state=42,
    )
    model.train(X_train, y_train)
    print("[retrain] Model training complete.")

    # 5. Evaluate
    print("\n[retrain] Phase 5: Evaluating model...")
    metrics = model.evaluate(X_test, y_test)
    print(f"[retrain] Accuracy:  {metrics['accuracy']:.4f}")
    print(f"[retrain] Precision: {metrics['precision']:.4f}")
    print(f"[retrain] Recall:    {metrics['recall']:.4f}")
    print(f"[retrain] F1-score:  {metrics['f1']:.4f}")

    print("\n[retrain] Per-class metrics:")
    report = metrics["classification_report"]
    for label in CLASS_LABELS:
        if label in report:
            r = report[label]
            print(
                f"[retrain]   {label:20s}  "
                f"precision={r['precision']:.4f}  "
                f"recall={r['recall']:.4f}  "
                f"f1={r['f1-score']:.4f}  "
                f"support={int(r['support'])}"
            )

    # 6. Feature importances
    print("\n[retrain] Top 5 feature importances:")
    importances = model.feature_importances()
    for name, imp in importances[:5]:
        print(f"[retrain]   {name:25s} {imp:.6f}")

    # 7. Save model
    print(f"\n[retrain] Phase 7: Saving model to {MODEL_PATH}...")
    model.save(MODEL_PATH)
    print(f"[retrain] Model saved successfully ({MODEL_PATH.stat().st_size / 1024:.0f} KB)")

    return model, metrics


if __name__ == "__main__":
    from typing import Tuple
    train()
