"""
Feature extraction: maps CICIDS2017 flow records to the 18-feature schema
used throughout the NIDS pipeline.

The 18-feature schema is defined in features.py and used by the Flow dataclass.
This module provides the bridge between the CICIDS2017 MachineLearningCSV
feature set (78 columns) and our simplified 18-feature schema, so that a
Random Forest model trained on CICIDS2017 can be applied to live traffic
extracted via Flow.get_features().
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from .features import NUMERIC_FEATURE_NAMES

# ---------------------------------------------------------------------------
# CICIDS2017 → NIDS 18-feature column mapping
# ---------------------------------------------------------------------------
# Each entry maps a NIDS feature name to the CICIDS2017 column name (or a
# lambda that computes it from the row).
CICIDS_COLUMN_MAPPING: Dict[str, str | callable] = {
    "duration": lambda df: df["Flow Duration"] / 1_000_000.0,
    "packet_count": lambda df: df["Total Fwd Packets"] + df["Total Backward Packets"],
    "byte_count": lambda df: df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"],
    "average_packet_size": lambda df: df["Average Packet Size"],
    "minimum_packet_size": "Min Packet Length",
    "maximum_packet_size": "Max Packet Length",
    "packet_size_std": "Packet Length Std",
    "packets_per_second": "Flow Packets/s",
    "bytes_per_second": "Flow Bytes/s",
    "forward_packets": "Total Fwd Packets",
    "backward_packets": "Total Backward Packets",
    "forward_bytes": "Total Length of Fwd Packets",
    "backward_bytes": "Total Length of Bwd Packets",
    "syn_count": "SYN Flag Count",
    "ack_count": "ACK Flag Count",
    "fin_count": "FIN Flag Count",
    "rst_count": "RST Flag Count",
    "psh_count": "PSH Flag Count",
}

# ---------------------------------------------------------------------------
# CICIDS2017 → NIDS 5-class label mapping
# ---------------------------------------------------------------------------
# CICIDS2017 uses granular attack labels.  We collapse them into 5 classes
# that match the rule engine's output categories.
#
# Mapping rationale:
#   - DoS, DDoS, Bot → DOS  (botnets are primarily used for DDoS)
#   - PortScan → PORT_SCAN
#   - BruteForce, WebAttack → BRUTE_FORCE
#     (CICIDS2017 Web Attacks include brute-force web login attacks)
#   - Infiltration → RECONNAISSANCE
#
LABEL_MAPPING: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "Benign": "BENIGN",
    "DoS": "DOS",
    "DoS GoldenEye": "DOS",
    "DoS Hulk": "DOS",
    "DoS Slowloris": "DOS",
    "DoS Slowhttptest": "DOS",
    "DDoS": "DOS",
    "PortScan": "PORT_SCAN",
    "Port Scan": "PORT_SCAN",
    "SSH Brute Force": "BRUTE_FORCE",
    "FTP-Patator": "BRUTE_FORCE",
    "BruteForce": "BRUTE_FORCE",
    "WebAttack": "BRUTE_FORCE",
    "Web Attack": "BRUTE_FORCE",
    "Web Attack Brute Force": "BRUTE_FORCE",
    "WebAttack BruteForce": "BRUTE_FORCE",
    "Heartbleed": "RECONNAISSANCE",
    "Infiltration": "RECONNAISSANCE",
    "Bot": "DOS",
    "Botnet": "DOS",
}

# Ordered list of the 5 output classes
CLASS_LABELS: List[str] = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]

# Reverse mapping for encoding labels to integers
LABEL_TO_INT: Dict[str, int] = {lbl: i for i, lbl in enumerate(CLASS_LABELS)}
INT_TO_LABEL: Dict[int, str] = {i: lbl for lbl, i in LABEL_TO_INT.items()}


def map_label(cicids_label: str) -> str:
    """
    Map a raw CICIDS2017 label string to one of the 5 NIDS class labels.

    Falls back to substring matching for variants not in the explicit
    LABEL_MAPPING dict.
    """
    if cicids_label in LABEL_MAPPING:
        return LABEL_MAPPING[cicids_label]

    lower = cicids_label.lower().strip()

    if "benign" in lower:
        return "BENIGN"
    if "dos" in lower or "ddos" in lower:
        return "DOS"
    if "portscan" in lower or "port scan" in lower:
        return "PORT_SCAN"
    if "bruteforce" in lower or "brute force" in lower or "ftp-patator" in lower:
        return "BRUTE_FORCE"
    if "webattack" in lower or "web attack" in lower:
        return "BRUTE_FORCE"
    if "infiltration" in lower:
        return "RECONNAISSANCE"
    if "heartbleed" in lower:
        return "RECONNAISSANCE"
    if "bot" in lower:
        return "DOS"

    raise ValueError(f"Cannot map CICIDS2017 label '{cicids_label}' to NIDS classes")


def extract_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Transform a raw CICIDS2017 DataFrame into the 18-feature schema.

    Args:
        df: Raw CICIDS2017 DataFrame (must contain the 78 columns + Label).

    Returns:
        Tuple of (features DataFrame with 18 columns, label Series with
        integer-encoded class labels matching CLASS_LABELS order).
    """
    feature_data = {}

    for feat_name in NUMERIC_FEATURE_NAMES:
        col_or_fn = CICIDS_COLUMN_MAPPING[feat_name]
        if callable(col_or_fn):
            feature_data[feat_name] = col_or_fn(df)
        else:
            feature_data[feat_name] = df[col_or_fn]

    features = pd.DataFrame(feature_data)

    # Sanitise: replace inf with NaN, then fill NaN with 0
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.fillna(0)

    # Encode labels
    labels = df["Label"].apply(map_label)
    labels_encoded = labels.map(LABEL_TO_INT)

    return features, labels_encoded


def load_cicids2017(csv_path: str | Path) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load a CICIDS2017 CSV file and transform it to the NIDS 18-feature schema.

    Args:
        csv_path: Path to the CICIDS2017 MachineLearningCSV file.

    Returns:
        (features, labels) tuple ready for model training.
    """
    df = pd.read_csv(csv_path)
    return extract_features(df)


def get_feature_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Return basic statistics for each of the 18 features."""
    features, _ = extract_features(df)
    return features.describe()
