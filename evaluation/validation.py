"""
STAGE 11.3: Dataset Validation
================================

Validates evaluation datasets and individual records.

Verdicts:
  VALID    — record is clean and ready for evaluation
  WARNING  — record has non-critical issues (e.g., missing optional fields)
  INVALID  — record has critical issues (e.g., wrong label, missing features)

The validator does NOT silently discard records. It reports all issues
and lets the caller decide whether to include or exclude each record.
"""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from NIDS.evaluation.schema import (
    CLASS_LABELS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationSession,
    ValidationIssue,
    ValidationVerdict,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataset-level validation
# ---------------------------------------------------------------------------

@dataclass
class DatasetValidationResult:
    """Result of validating an entire dataset."""
    total_records: int = 0
    valid_count: int = 0
    warning_count: int = 0
    invalid_count: int = 0
    issues: List[ValidationIssue] = field(default_factory=list)
    label_distribution: Dict[str, int] = field(default_factory=dict)
    session_distribution: Dict[str, int] = field(default_factory=dict)
    duplicate_feature_count: int = 0
    overlapping_sessions: List[str] = field(default_factory=list)
    is_usable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_records": self.total_records,
            "valid_count": self.valid_count,
            "warning_count": self.warning_count,
            "invalid_count": self.invalid_count,
            "issues": [
                {"code": i.code, "message": i.message, "record_id": i.record_id}
                for i in self.issues
            ],
            "label_distribution": self.label_distribution,
            "session_distribution": self.session_distribution,
            "duplicate_feature_count": self.duplicate_feature_count,
            "overlapping_sessions": self.overlapping_sessions,
            "is_usable": self.is_usable,
        }


def validate_dataset(dataset: EvaluationDataset) -> DatasetValidationResult:
    """
    Validate an entire EvaluationDataset.

    Checks:
      - Record-level validation (already done in add_record)
      - Label coverage (all classes present)
      - Minimum samples per class
      - Duplicate feature vectors
      - Overlapping collection sessions
      - Impossible timestamps
    """
    result = DatasetValidationResult(
        total_records=len(dataset.records),
        label_distribution=dataset.label_distribution(),
        session_distribution={
            sid: len(dataset.get_records_by_session(sid))
            for sid in dataset.sessions
        },
    )

    # Count verdicts
    for r in dataset.records:
        verdict = r.verdict()
        if verdict == ValidationVerdict.VALID:
            result.valid_count += 1
        elif verdict == ValidationVerdict.WARNING:
            result.warning_count += 1
        else:
            result.invalid_count += 1

    result.issues = list(dataset.validation_issues)

    # Check label coverage
    missing_labels = [lbl for lbl in CLASS_LABELS if result.label_distribution.get(lbl, 0) == 0]
    if missing_labels:
        result.issues.append(ValidationIssue(
            "missing_labels",
            f"Dataset has no samples for classes: {missing_labels}",
        ))
        result.is_usable = False

    # Check minimum samples per class (warn if < 10)
    for lbl, count in result.label_distribution.items():
        if count < 10:
            result.issues.append(ValidationIssue(
                "insufficient_samples",
                f"Class {lbl} has only {count} samples (minimum recommended: 10)",
            ))

    # Check for duplicate feature vectors
    feature_tuples = [tuple(r.features) for r in dataset.records]
    unique_features = set(feature_tuples)
    result.duplicate_feature_count = len(feature_tuples) - len(unique_features)
    if result.duplicate_feature_count > 0:
        result.issues.append(ValidationIssue(
            "duplicate_features",
            f"Dataset contains {result.duplicate_feature_count} duplicate feature vectors",
        ))

    # Check for overlapping sessions
    sessions = list(dataset.sessions.values())
    for i in range(len(sessions)):
        for j in range(i + 1, len(sessions)):
            s1, s2 = sessions[i], sessions[j]
            if s1.start_timestamp < s2.end_timestamp and s2.start_timestamp < s1.end_timestamp:
                overlap = f"{s1.session_id} <-> {s2.session_id}"
                result.overlapping_sessions.append(overlap)
                result.issues.append(ValidationIssue(
                    "overlapping_sessions",
                    f"Sessions {overlap} overlap in time",
                ))

    # Check for impossible timestamps
    now = time.time()
    for r in dataset.records:
        if r.collection_timestamp > now + 3600:
            result.issues.append(ValidationIssue(
                "future_timestamp",
                f"Record has timestamp in the future: {r.collection_timestamp}",
            ))

    # Usability decision
    if result.invalid_count > len(dataset.records) * 0.1:
        result.is_usable = False
        result.issues.append(ValidationIssue(
            "too_many_invalid",
            f"More than 10% of records are INVALID ({result.invalid_count}/{len(dataset.records)})",
        ))

    return result


# ---------------------------------------------------------------------------
# Record-level validation helpers
# ---------------------------------------------------------------------------

def validate_record(record: EvaluationRecord) -> DatasetValidationResult:
    """
    Validate a single record and return a summary result.
    """
    result = DatasetValidationResult(
        total_records=1,
        label_distribution={record.ground_truth_label: 1},
    )

    verdict = record.verdict()
    if verdict == ValidationVerdict.VALID:
        result.valid_count = 1
    elif verdict == ValidationVerdict.WARNING:
        result.warning_count = 1
    else:
        result.invalid_count = 1

    result.issues = record.validate()
    result.is_usable = verdict != ValidationVerdict.INVALID
    return result


def validate_session(session: EvaluationSession) -> DatasetValidationResult:
    """
    Validate a collection session metadata.
    """
    result = DatasetValidationResult()

    if not session.session_id:
        result.issues.append(ValidationIssue("missing_session_id", "session_id is empty"))
        result.is_usable = False

    if session.end_timestamp <= session.start_timestamp:
        result.issues.append(ValidationIssue(
            "invalid_duration",
            f"Session end ({session.end_timestamp}) <= start ({session.start_timestamp})",
        ))
        result.is_usable = False

    if session.traffic_category not in ("BENIGN", "ATTACK"):
        result.issues.append(ValidationIssue(
            "invalid_traffic_category",
            f"traffic_category '{session.traffic_category}' is invalid",
        ))
        result.is_usable = False

    if not session.interface:
        result.issues.append(ValidationIssue("missing_interface", "interface is empty"))

    if not session.source_machine:
        result.issues.append(ValidationIssue("missing_source", "source_machine is empty"))

    if not session.target_machine:
        result.issues.append(ValidationIssue("missing_target", "target_machine is empty"))

    return result
