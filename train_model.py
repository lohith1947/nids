"""
Training script for the NIDS Random Forest model.

Usage:
    python -m NIDS.train_model

This script will:
1. Download (or load) the CICIDS2017 sample dataset from GitHub.
2. Extract the 18 NIDS features using data_extractor.py.
3. Split into train/test (80/20).
4. Train a Random Forest classifier with StandardScaler.
5. Evaluate on the test set.
6. Save the trained model to models/nids_model.joblib.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from urllib.request import urlretrieve

# Ensure stdout can handle Unicode paths on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import numpy as np

from .data_extractor import CLASS_LABELS, load_cicids2017
from .model import NIDSModel

# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
# Small sample dataset (56K rows) from a GitHub mirror of the official
# CICIDS2017 MachineLearningCSV files.  Sufficient for training a
# prototype Random Forest model.
DATASET_URL = "https://raw.githubusercontent.com/NirmalaKTomar/CICIDS2017_Sample_dataset/main/CICIDS2017_sample.csv"
DATASET_FILENAME = "CICIDS2017_sample.csv"

# Output
MODEL_DIR = Path(__file__).parent / "models"
MODEL_PATH = MODEL_DIR / "nids_model.joblib"


def download_dataset(dest: Path) -> Path:
    """Download the CICIDS2017 sample CSV if it does not already exist."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"[train] Dataset already downloaded at {dest}")
        return dest

    print(f"[train] Downloading dataset from GitHub...")
    print(f"[train]   URL: {DATASET_URL}")
    print(f"[train]   Dest: {dest}")

    def _progress(block_num, block_size, total_size):
        if total_size > 0:
            pct = (block_num * block_size) / total_size * 100
            sys.stdout.write(f"\r[train]   Downloading: {pct:.1f}%")
            sys.stdout.flush()

    urlretrieve(DATASET_URL, str(dest), reporthook=_progress)
    sys.stdout.write("\n")
    print(f"[train] Dataset saved ({dest.stat().st_size / 1024:.0f} KB)")
    return dest


def train():
    """
    Main training pipeline.

    Downloads the CICIDS2017 sample dataset, extracts the 18 NIDS features,
    trains a Random Forest model, evaluates it, and saves the trained model.
    """
    np.random.seed(42)

    # 1. Download dataset
    csv_path = download_dataset(Path(tempfile.gettempdir()) / "cicids2017" / DATASET_FILENAME)

    # 2. Load and extract features
    print("[train] Loading and extracting features...")
    X, y = load_cicids2017(csv_path)
    print(f"[train] Features shape: {X.shape}")
    print(f"[train] Labels shape: {y.shape}")

    # Print label distribution
    label_counts = y.value_counts().sort_index()
    print("[train] Label distribution:")
    for idx, count in label_counts.items():
        print(f"[train]   {CLASS_LABELS[idx]}: {count} ({count / len(y) * 100:.1f}%)")

    # 3. Train/test split
    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y.values, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[train] Train set: {X_train.shape[0]} samples")
    print(f"[train] Test set:  {X_test.shape[0]} samples")

    # 4. Train model
    print("[train] Training Random Forest model (this may take a minute)...")
    model = NIDSModel(
        n_estimators=200,
        max_depth=20,
        random_state=42,
    )
    model.train(X_train, y_train)
    print("[train] Model training complete.")

    # 5. Evaluate
    print("[train] Evaluating model...")
    metrics = model.evaluate(X_test, y_test)
    print(f"[train] Accuracy:  {metrics['accuracy']:.4f}")
    print(f"[train] Precision: {metrics['precision']:.4f}")
    print(f"[train] Recall:    {metrics['recall']:.4f}")
    print(f"[train] F1-score:  {metrics['f1']:.4f}")

    # Per-class report
    print("[train] Per-class metrics:")
    report = metrics["classification_report"]
    for label in CLASS_LABELS:
        if label in report:
            r = report[label]
            print(
                f"[train]   {label:20s}  "
                f"precision={r['precision']:.4f}  "
                f"recall={r['recall']:.4f}  "
                f"f1={r['f1-score']:.4f}  "
                f"support={int(r['support'])}"
            )

    # Feature importances
    print("[train] Top 5 feature importances:")
    importances = model.feature_importances()
    for name, imp in importances[:5]:
        print(f"[train]   {name:25s} {imp:.6f}")

    # 6. Save model
    print(f"[train] Saving model to {MODEL_PATH}...")
    model.save(MODEL_PATH)
    print(f"[train] Model saved successfully ({MODEL_PATH.stat().st_size / 1024:.0f} KB)")

    return model, metrics


if __name__ == "__main__":
    train()
