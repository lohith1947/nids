"""
NIDS Random Forest model wrapper.

Wraps a scikit-learn RandomForestClassifier with a StandardScaler so that
the 18-feature schema from features.py / Flow.get_features() can be fed
directly to the trained model.

Usage (training):
    from NIDS.model import NIDSModel
    model = NIDSModel()
    model.train(X, y)
    model.save("models/nids_model.joblib")

Usage (inference):
    from NIDS.model import NIDSModel
    model = NIDSModel.load("models/nids_model.joblib")
    features = [0.1, 1, 64, ...]  # 18 floats from Flow.get_features()
    label, confidence = model.predict(features)
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple, Union

import numpy as np
from joblib import dump, load
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .data_extractor import CLASS_LABELS


class NIDSModel:
    """
    Wrapper around RandomForest + StandardScaler for NIDS classification.

    The model predicts one of 5 classes:
    BENIGN, PORT_SCAN, BRUTE_FORCE, DOS, RECONNAISSANCE
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: Optional[int] = None,
        random_state: int = 42,
    ):
        self.scaler = StandardScaler()
        self.clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
        )
        self._is_fitted = False

    @property
    def classes_(self) -> List[str]:
        """Return class labels in the order matching the classifier's internal encoding.

        When the model is fitted, labels are derived from ``clf.classes_`` (the
        actual integer class values seen during training) mapped through
        ``CLASS_LABELS``.  Before fitting, falls back to the full ``CLASS_LABELS``
        list so callers can inspect the expected schema.
        """
        if not self._is_fitted or self.clf is None:
            return list(CLASS_LABELS)
        return [CLASS_LABELS[int(c)] for c in self.clf.classes_]

    def _label_for_int(self, int_label: int) -> str:
        """Map an integer class label to its string name from CLASS_LABELS."""
        return CLASS_LABELS[int(int_label)]

    def train(
        self,
        X: np.ndarray | List[List[float]],
        y: np.ndarray | List[int],
    ) -> "NIDSModel":
        """
        Train the model on feature matrix X and label vector y.

        Args:
            X: Array of shape (n_samples, 18) with the 18 numeric features.
            y: Array of shape (n_samples,) with integer class labels
               (0=BENIGN, 1=PORT_SCAN, 2=BRUTE_FORCE, 3=DOS, 4=RECONNAISSANCE).

        Returns:
            self (for method chaining).
        """
        X_arr = np.asarray(X, dtype=np.float64)
        y_arr = np.asarray(y, dtype=np.int64)

        X_scaled = self.scaler.fit_transform(X_arr)
        self.clf.fit(X_scaled, y_arr)
        self._is_fitted = True

        # Validate that all 5 classes are present in training.
        # If any leading class is absent, clf.classes_ will not be [0..4]
        # and label mapping would silently corrupt predictions.
        present_classes = {int(c) for c in self.clf.classes_}
        all_classes = set(range(len(CLASS_LABELS)))
        missing = all_classes - present_classes
        if missing:
            missing_names = [CLASS_LABELS[i] for i in sorted(missing)]
            raise ValueError(
                f"Model trained without required classes: {missing_names}. "
                f"All 5 classes ({CLASS_LABELS}) must be present in training data."
            )

        return self

    def predict(
        self,
        features: Union[List[float], np.ndarray, "List[List[float]]"],
    ) -> Tuple[str, float]:
        """
        Predict the class label for a single flow.

        Args:
            features: Either a single 18-element list (one flow) or a
                      list of lists (multiple flows).

        Returns:
            (label, confidence) for a single flow, or (labels_list, confs_list)
            for multiple flows.  Confidence is the probability of the predicted
            class.
        """
        if not self._is_fitted:
            raise RuntimeError("Model has not been trained. Call train() first or load a saved model.")

        arr = np.asarray(features, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
            single = True
        else:
            single = False

        arr_scaled = self.scaler.transform(arr)
        probs = self.clf.predict_proba(arr_scaled)
        pred_values = self.clf.predict(arr_scaled)

        # Map each predicted integer class value to its label name.
        # Using CLASS_LABELS[int(value)] is correct because CLASS_LABELS is
        # indexed by the integer class values (0=BENIGN, 1=PORT_SCAN, ...).
        pred_labels = [CLASS_LABELS[int(v)] for v in pred_values]

        # Confidence = probability of the predicted class.
        # Find the column index of each predicted class in clf.classes_
        # (probs columns are ordered by clf.classes_, not by integer value).
        class_to_col = {int(c): idx for idx, c in enumerate(self.clf.classes_)}
        confidences = [
            float(probs[i, class_to_col[int(pred_values[i])]])
            for i in range(len(pred_values))
        ]

        if single:
            return pred_labels[0], confidences[0]
        return pred_labels, confidences

    def evaluate(
        self,
        X: np.ndarray | List[List[float]],
        y: np.ndarray | List[int],
    ) -> dict:
        """
        Evaluate the model and return a metrics dictionary.

        Returns:
            dict with keys: accuracy, precision, recall, f1, classification_report, confusion_matrix
        """
        from sklearn.metrics import (
            accuracy_score,
            classification_report,
            confusion_matrix,
            f1_score,
            precision_score,
            recall_score,
        )

        arr = np.asarray(X, dtype=np.float64)
        arr_scaled = self.scaler.transform(arr)
        y_pred = self.clf.predict(arr_scaled)

        return {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
            "recall": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
            "f1": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
            "classification_report": classification_report(
                y, y_pred, target_names=CLASS_LABELS, zero_division=0, output_dict=True
            ),
            "confusion_matrix": confusion_matrix(y, y_pred).tolist(),
        }

    def feature_importances(self) -> List[Tuple[str, float]]:
        """
        Return list of (feature_name, importance) sorted descending.
        Feature names come from features.NUMERIC_FEATURE_NAMES.
        """
        from .features import NUMERIC_FEATURE_NAMES

        importances = self.clf.feature_importances_
        pairs = list(zip(NUMERIC_FEATURE_NAMES, importances))
        pairs.sort(key=lambda x: x[1], reverse=True)
        return pairs

    def save(self, path: str | Path) -> None:
        """Persist the scaler + classifier to a joblib file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        dump({"scaler": self.scaler, "clf": self.clf}, str(path))

    @classmethod
    def load(cls, path: str | Path) -> "NIDSModel":
        """Load a saved model from a joblib file."""
        path = Path(path)
        bundle = load(str(path))
        model = cls.__new__(cls)
        model.scaler = bundle["scaler"]
        model.clf = bundle["clf"]
        model._is_fitted = True

        # Validate that all 5 classes are present in the loaded model.
        present_classes = {int(c) for c in model.clf.classes_}
        all_classes = set(range(len(CLASS_LABELS)))
        missing = all_classes - present_classes
        if missing:
            missing_names = [CLASS_LABELS[i] for i in sorted(missing)]
            raise ValueError(
                f"Loaded model missing required classes: {missing_names}. "
                f"All 5 classes ({CLASS_LABELS}) must be present. "
                f"Re-train with a balanced dataset."
            )

        return model
