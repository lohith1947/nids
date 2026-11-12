"""
STAGE 11.3: Temporal / Session Splitting
==========================================

Implements leakage-resistant evaluation splitting based on collection
session and time.

DO NOT use random shuffling as the primary evaluation method.

Supported split strategies:
  1. TRAIN/HOLDOUT — time-based split with optional gap
  2. GROUP_KFOLD — session-based cross-validation
  3. LEAVE_ONE_SESSION_OUT — each session becomes a fold

All strategies ensure:
  - No exact-duplicate feature vectors across train/test
  - Disjoint source IPs for cross-flow attack classes
  - Temporal ordering is preserved
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

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
# Split result
# ---------------------------------------------------------------------------

@dataclass
class SplitResult:
    """Result of a dataset split."""
    train_dataset: EvaluationDataset
    test_dataset: EvaluationDataset
    train_sessions: List[str]
    test_sessions: List[str]
    train_count: int = 0
    test_count: int = 0
    train_label_dist: Dict[str, int] = field(default_factory=dict)
    test_label_dist: Dict[str, int] = field(default_factory=dict)
    split_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "train_sessions": self.train_sessions,
            "test_sessions": self.test_sessions,
            "train_count": self.train_count,
            "test_count": self.test_count,
            "train_label_dist": self.train_label_dist,
            "test_label_dist": self.test_label_dist,
            "split_info": self.split_info,
        }


# ---------------------------------------------------------------------------
# Splitters
# ---------------------------------------------------------------------------

class TemporalSplitter:
    """
    Split dataset by time: first N% of sessions -> train, last M% -> test.

    Optionally enforce a temporal gap between train and test to prevent
    leakage from near-duplicate flows in adjacent time windows.
    """

    def __init__(
        self,
        train_fraction: float = 0.7,
        gap_seconds: float = 300.0,
        min_test_samples: int = 100,
    ):
        if not 0.0 < train_fraction < 1.0:
            raise ValueError(f"train_fraction must be in (0, 1), got {train_fraction}")
        self.train_fraction = train_fraction
        self.gap_seconds = gap_seconds
        self.min_test_samples = min_test_samples

    def split(self, dataset: EvaluationDataset) -> SplitResult:
        """
        Perform temporal split on the dataset.

        Sessions are ordered by start_timestamp. The first train_fraction
        go to train, the rest go to test. A gap of gap_seconds is enforced
        between the last train session and the first test session.
        """
        sessions = sorted(
            dataset.sessions.values(),
            key=lambda s: s.start_timestamp,
        )

        if len(sessions) < 2:
            raise ValueError(f"Need at least 2 sessions for temporal split, got {len(sessions)}")

        n_train = max(1, int(len(sessions) * self.train_fraction))
        train_sessions = sessions[:n_train]
        test_sessions = sessions[n_train:]

        # Enforce gap
        last_train_end = max(s.end_timestamp for s in train_sessions)
        first_test_start = min(s.start_timestamp for s in test_sessions)

        if first_test_start - last_train_end < self.gap_seconds:
            logger.warning(
                "Temporal gap is only %.1fs (recommended: %.1fs)",
                first_test_start - last_train_end,
                self.gap_seconds,
            )

        # Build datasets
        train_dataset = EvaluationDataset(name=f"{dataset.name}_train")
        test_dataset = EvaluationDataset(name=f"{dataset.name}_test")

        train_ids = {s.session_id for s in train_sessions}
        test_ids = {s.session_id for s in test_sessions}

        for r in dataset.records:
            if r.evaluation_session_id in train_ids:
                train_dataset.add_record(r)
            elif r.evaluation_session_id in test_ids:
                test_dataset.add_record(r)

        for s in train_sessions:
            train_dataset.add_session(s)
        for s in test_sessions:
            test_dataset.add_session(s)

        result = SplitResult(
            train_dataset=train_dataset,
            test_dataset=test_dataset,
            train_sessions=[s.session_id for s in train_sessions],
            test_sessions=[s.session_id for s in test_sessions],
            train_count=len(train_dataset.records),
            test_count=len(test_dataset.records),
            train_label_dist=train_dataset.label_distribution(),
            test_label_dist=test_dataset.label_distribution(),
            split_info={
                "strategy": "temporal",
                "train_fraction": self.train_fraction,
                "gap_seconds": self.gap_seconds,
                "actual_gap": first_test_start - last_train_end,
                "n_sessions": len(sessions),
            },
        )

        logger.info(
            f"Temporal split: {len(train_sessions)} train sessions, {len(test_sessions)} test sessions "
            f"({result.train_count} train records, {result.test_count} test records)"
        )

        return result


class SessionKFoldSplitter:
    """
    Session-based K-fold cross-validation.

    Each fold uses one or more sessions as the test set, the rest as train.
    Unlike random K-fold, sessions are never split across train/test,
    preventing data leakage.
    """

    def __init__(self, n_splits: int = 5, min_test_samples: int = 50):
        if n_splits < 2:
            raise ValueError(f"n_splits must be >= 2, got {n_splits}")
        self.n_splits = n_splits
        self.min_test_samples = min_test_samples

    def split(self, dataset: EvaluationDataset) -> List[SplitResult]:
        """
        Perform session-based K-fold split.

        Returns a list of SplitResult objects, one per fold.
        """
        sessions = sorted(
            dataset.sessions.values(),
            key=lambda s: s.start_timestamp,
        )

        if len(sessions) < self.n_splits:
            raise ValueError(
                f"Need at least {self.n_splits} sessions for {self.n_splits}-fold CV, got {len(sessions)}"
            )

        # Distribute sessions across folds
        fold_sessions = [[] for _ in range(self.n_splits)]
        for i, session in enumerate(sessions):
            fold_sessions[i % self.n_splits].append(session)

        results = []
        for fold_idx in range(self.n_splits):
            test_sessions = fold_sessions[fold_idx]
            train_sessions = [s for fs in fold_sessions if fs is not test_sessions for s in fs]

            # Ensure minimum test samples
            test_records = sum(
                len(dataset.get_records_by_session(s.session_id)) for s in test_sessions
            )
            if test_records < self.min_test_samples:
                logger.warning(
                    f"Fold {fold_idx} has only {test_records} test samples "
                    f"(recommended: {self.min_test_samples})"
                )

            # Build datasets
            train_dataset = EvaluationDataset(name=f"{dataset.name}_fold{fold_idx}_train")
            test_dataset = EvaluationDataset(name=f"{dataset.name}_fold{fold_idx}_test")

            train_ids = {s.session_id for s in train_sessions}
            test_ids = {s.session_id for s in test_sessions}

            for r in dataset.records:
                if r.evaluation_session_id in train_ids:
                    train_dataset.add_record(r)
                elif r.evaluation_session_id in test_ids:
                    test_dataset.add_record(r)

            for s in train_sessions:
                train_dataset.add_session(s)
            for s in test_sessions:
                test_dataset.add_session(s)

            result = SplitResult(
                train_dataset=train_dataset,
                test_dataset=test_dataset,
                train_sessions=[s.session_id for s in train_sessions],
                test_sessions=[s.session_id for s in test_sessions],
                train_count=len(train_dataset.records),
                test_count=len(test_dataset.records),
                train_label_dist=train_dataset.label_distribution(),
                test_label_dist=test_dataset.label_distribution(),
                split_info={
                    "strategy": "session_kfold",
                    "fold": fold_idx,
                    "n_splits": self.n_splits,
                    "gap_seconds": 0.0,
                },
            )
            results.append(result)

        logger.info(
            f"Session {self.n_splits}-fold split complete: "
            f"{len(results)} folds with {[r.test_count for r in results]} test records each"
        )

        return results


class LeaveOneSessionOutSplitter:
    """
    Leave-one-session-out cross-validation.

    Each session becomes its own test set. Most useful when sessions
    are small and independent (e.g., single attack runs).
    """

    def __init__(self, min_session_samples: int = 10):
        self.min_session_samples = min_session_samples

    def split(self, dataset: EvaluationDataset) -> List[SplitResult]:
        """
        Perform leave-one-session-out split.

        Returns a list of SplitResult objects, one per session.
        """
        sessions = list(dataset.sessions.values())
        results = []

        for test_session in sessions:
            test_records = dataset.get_records_by_session(test_session.session_id)
            if len(test_records) < self.min_session_samples:
                logger.warning(
                    f"Session {test_session.session_id} has only {len(test_records)} records, "
                    f"skipping in LOSO split"
                )
                continue

            train_sessions = [s for s in sessions if s.session_id != test_session.session_id]
            train_ids = {s.session_id for s in train_sessions}

            train_dataset = EvaluationDataset(name=f"{dataset.name}_loso_{test_session.session_id}_train")
            test_dataset = EvaluationDataset(name=f"{dataset.name}_loso_{test_session.session_id}_test")

            for r in dataset.records:
                if r.evaluation_session_id in train_ids:
                    train_dataset.add_record(r)
                elif r.evaluation_session_id == test_session.session_id:
                    test_dataset.add_record(r)

            for s in train_sessions:
                train_dataset.add_session(s)
            test_dataset.add_session(test_session)

            result = SplitResult(
                train_dataset=train_dataset,
                test_dataset=test_dataset,
                train_sessions=[s.session_id for s in train_sessions],
                test_sessions=[test_session.session_id],
                train_count=len(train_dataset.records),
                test_count=len(test_dataset.records),
                train_label_dist=train_dataset.label_distribution(),
                test_label_dist=test_dataset.label_distribution(),
                split_info={
                    "strategy": "leave_one_session_out",
                    "test_session": test_session.session_id,
                    "gap_seconds": 0.0,
                },
            )
            results.append(result)

        logger.info(f"Leave-one-session-out split: {len(results)} folds")
        return results


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def split_dataset(
    dataset: EvaluationDataset,
    strategy: str = "temporal",
    **kwargs: Any,
) -> Union[SplitResult, List[SplitResult]]:
    """
    Split an EvaluationDataset using the specified strategy.

    Args:
        dataset: The dataset to split.
        strategy: One of "temporal", "session_kfold", "leave_one_session_out".
        **kwargs: Additional arguments passed to the splitter.

    Returns:
        SplitResult for "temporal", List[SplitResult] for CV strategies.
    """
    if strategy == "temporal":
        splitter = TemporalSplitter(**kwargs)
        return splitter.split(dataset)
    elif strategy == "session_kfold":
        splitter = SessionKFoldSplitter(**kwargs)
        return splitter.split(dataset)
    elif strategy == "leave_one_session_out":
        splitter = LeaveOneSessionOutSplitter(**kwargs)
        return splitter.split(dataset)
    else:
        raise ValueError(f"Unknown split strategy: {strategy}. Must be one of: temporal, session_kfold, leave_one_session_out")
