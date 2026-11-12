"""
STAGE 11.3: Evaluation Harness — Data Schema and Core Types
================================================================

Defines the canonical schema for evaluation records and shared constants.
All evaluation datasets use this schema to ensure consistency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 18-feature names in canonical order (from NIDS.features)
FEATURE_NAMES: List[str] = [
    "duration",
    "packet_count",
    "byte_count",
    "average_packet_size",
    "minimum_packet_size",
    "maximum_packet_size",
    "packet_size_std",
    "packets_per_second",
    "bytes_per_second",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
]

# Valid ground-truth labels
CLASS_LABELS: List[str] = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "DOS", "RECONNAISSANCE"]

# Traffic categories
TRAFFIC_CATEGORY_BENIGN = "BENIGN"
TRAFFIC_CATEGORY_ATTACK = "ATTACK"

# Capture interfaces
INTERFACE_LOOPBACK = "loopback"
INTERFACE_HOST_ONLY = "host_only"
INTERFACE_EXTERNAL = "external"

# Validation verdicts
class ValidationVerdict(Enum):
    VALID = "VALID"
    WARNING = "WARNING"
    INVALID = "INVALID"


# ---------------------------------------------------------------------------
# Evaluation Record Schema
# ---------------------------------------------------------------------------

@dataclass
class EvaluationRecord:
    """
    Canonical schema for a single labeled flow in the evaluation dataset.

    ground_truth_label MUST be assigned independently of:
      - model prediction
      - rule prediction
      - correlation result
      - risk score
      - alert result

    The NIDS must never label its own predictions as ground truth.
    """

    # --- Session / provenance ---
    evaluation_session_id: str
    collection_timestamp: float
    traffic_category: str  # BENIGN or ATTACK
    traffic_subtype: str   # e.g. "loopback_tcp", "nmap_scan", "hping3_flood"

    # --- Ground truth (assigned by collection script, NOT by NIDS) ---
    ground_truth_label: str

    # --- Flow identity ---
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # --- 18 ML features (canonical order) ---
    features: List[float]

    # --- Model output (populated during evaluation, None during collection) ---
    model_prediction: Optional[str] = None
    model_confidence: Optional[float] = None
    model_probabilities: Optional[Dict[str, float]] = None

    # --- Rule Engine output (optional) ---
    rule_prediction: Optional[str] = None
    rule_confidence: Optional[float] = None
    rule_triggered: Optional[List[str]] = None

    # --- Correlation output (optional) ---
    correlation_prediction: Optional[str] = None
    correlation_confidence: Optional[float] = None

    # --- Alert output (optional) ---
    alert_generated: Optional[bool] = None
    alert_risk_score: Optional[float] = None
    alert_severity: Optional[str] = None

    # --- Metadata ---
    flow_duration: Optional[float] = None
    packet_count: Optional[int] = None
    byte_count: Optional[int] = None
    collection_interface: Optional[str] = None
    source_machine: Optional[str] = None
    target_machine: Optional[str] = None
    generator_command: Optional[str] = None
    generator_log: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluationRecord":
        """Deserialize from a dictionary."""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "EvaluationRecord":
        """Deserialize from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def validate(self) -> List["ValidationIssue"]:
        """
        Validate this record and return a list of issues.

        Returns an empty list if the record is VALID.
        """
        issues: List[ValidationIssue] = []

        # Required fields
        if not self.evaluation_session_id:
            issues.append(ValidationIssue("missing_session_id", "evaluation_session_id is empty"))
        if self.ground_truth_label not in CLASS_LABELS:
            issues.append(ValidationIssue("invalid_label", f"ground_truth_label '{self.ground_truth_label}' is not in {CLASS_LABELS}"))
        if self.traffic_category not in (TRAFFIC_CATEGORY_BENIGN, TRAFFIC_CATEGORY_ATTACK):
            issues.append(ValidationIssue("invalid_category", f"traffic_category '{self.traffic_category}' is invalid"))
        if len(self.features) != 18:
            issues.append(ValidationIssue("wrong_feature_count", f"Expected 18 features, got {len(self.features)}"))
        if self.collection_timestamp <= 0:
            issues.append(ValidationIssue("invalid_timestamp", "collection_timestamp is missing or invalid"))

        # Feature sanity checks
        for i, (name, val) in enumerate(zip(FEATURE_NAMES, self.features)):
            if val is None:
                issues.append(ValidationIssue(f"missing_feature_{name}", f"Feature '{name}' (index {i}) is None"))
            elif isinstance(val, (int, float)) and (val < -1e9 or val > 1e9):
                issues.append(ValidationIssue(f"out_of_range_feature_{name}", f"Feature '{name}' = {val} is out of reasonable range"))

        # 5-tuple sanity
        if not self.src_ip or not self.dst_ip:
            issues.append(ValidationIssue("missing_ip", "src_ip or dst_ip is empty"))
        if self.protocol not in (1, 6, 17):
            issues.append(ValidationIssue("invalid_protocol", f"protocol {self.protocol} is not 1 (ICMP), 6 (TCP), or 17 (UDP)"))

        return issues

    def verdict(self) -> ValidationVerdict:
        """
        Return the validation verdict for this record.

        VALID    — no issues
        WARNING  — non-critical issues (e.g., missing optional fields)
        INVALID  — critical issues (e.g., wrong label, missing features)
        """
        issues = self.validate()
        if not issues:
            return ValidationVerdict.VALID

        critical_keywords = ["missing", "invalid", "wrong_feature_count"]
        has_critical = any(
            any(kw in issue.code for kw in critical_keywords)
            for issue in issues
        )
        if has_critical:
            return ValidationVerdict.INVALID
        return ValidationVerdict.WARNING


@dataclass
class ValidationIssue:
    """A single validation issue found in an evaluation record."""
    code: str
    message: str
    record_id: Optional[str] = None

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


@dataclass
class EvaluationSession:
    """
    Metadata for a collection session.

    A session is the atomic unit of splitting to prevent data leakage.
    """
    session_id: str
    start_timestamp: float
    end_timestamp: float
    traffic_category: str
    traffic_subtype: str
    interface: str
    source_machine: str
    target_machine: str
    generator_command: Optional[str] = None
    generator_log_path: Optional[str] = None
    output_path: Optional[str] = None
    record_count: int = 0
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def duration_seconds(self) -> float:
        return self.end_timestamp - self.start_timestamp


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------

class EvaluationDataset:
    """
    In-memory representation of an evaluation dataset.

    Provides methods for:
      - Adding records
      - Validating records
      - Computing statistics
      - Serializing to/from JSON Lines
    """

    def __init__(self, name: str = "unnamed"):
        self.name = name
        self.records: List[EvaluationRecord] = []
        self.sessions: Dict[str, EvaluationSession] = {}
        self.validation_issues: List[ValidationIssue] = []

    def add_record(self, record: EvaluationRecord) -> None:
        """Add a record and run validation."""
        self.records.append(record)
        issues = record.validate()
        self.validation_issues.extend(issues)

    def add_session(self, session: EvaluationSession) -> None:
        """Register a collection session."""
        self.sessions[session.session_id] = session

    def get_records_by_session(self, session_id: str) -> List[EvaluationRecord]:
        """Return all records from a given session."""
        return [r for r in self.records if r.evaluation_session_id == session_id]

    def get_records_by_label(self, label: str) -> List[EvaluationRecord]:
        """Return all records with a given ground-truth label."""
        return [r for r in self.records if r.ground_truth_label == label]

    def label_distribution(self) -> Dict[str, int]:
        """Return the count of records per ground-truth label."""
        dist: Dict[str, int] = {lbl: 0 for lbl in CLASS_LABELS}
        for r in self.records:
            if r.ground_truth_label in dist:
                dist[r.ground_truth_label] += 1
        return dist

    def validation_summary(self) -> Dict[str, int]:
        """Return counts of VALID, WARNING, and INVALID records."""
        counts = {"VALID": 0, "WARNING": 0, "INVALID": 0}
        for r in self.records:
            counts[r.verdict().value] += 1
        return counts

    def valid_records(self) -> List[EvaluationRecord]:
        """Return only VALID records."""
        return [r for r in self.records if r.verdict() == ValidationVerdict.VALID]

    def to_jsonl(self, path: Union[str, Path]) -> None:
        """Write all records to a JSON Lines file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for record in self.records:
                f.write(record.to_json() + "\n")

    @classmethod
    def from_jsonl(cls, path: Union[str, Path], name: str = "loaded") -> "EvaluationDataset":
        """Load records from a JSON Lines file."""
        path = Path(path)
        dataset = cls(name=name)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = EvaluationRecord.from_json(line)
                    dataset.add_record(record)
                except (json.JSONDecodeError, TypeError) as e:
                    dataset.validation_issues.append(
                        ValidationIssue("parse_error", f"Failed to parse line: {e}")
                    )
        return dataset
