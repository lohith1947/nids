"""
Stage 4: Alert System for the NIDS.

Consumes a DetectionResult (from CorrelationEngine) + RiskResult (from
RiskScorer) + Flow metadata and produces structured Alert objects
with deduplication, rate limiting, severity filtering, and thread-safe
in-memory storage.

Integration point:
    RiskScorer -> (RiskResult) -> AlertManager.create_alert(...)

Design notes
------------
- Deduplication: a deterministic key built from the 5-tuple + attack_type
  ensures that repeated identical detections within a configurable time
  window (default 30 s) are collapsed into a single alert with an
  incremented "count" field.  This prevents alert flooding from
  long-running attacks that produce many flows.

- Rate limiting: per source IP, a maximum number of alerts (default 10)
  is allowed per deduplication window.  Excess alerts are recorded as
  "rate_limited" (not silently dropped) so the dashboard can show
  suppressed volume.

- Severity filtering: a configurable minimum severity (default "LOW"
  meaning all severities pass) lets the pipeline suppress
  INFORMATIONAL / low-risk detections without code changes.

- Thread safety: a single threading.Lock guards the alert list and
  deduplication/rate-limit auxiliary state.  This is deliberately
  simple — contention is expected to be low because alerts are emitted
  only on flow completion, not per packet.
"""

from __future__ import annotations

import threading
import uuid
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from .risk_scorer import RiskResult
from .rule_engine import (
    BENIGN,
    PORT_SCAN,
    BRUTE_FORCE,
    DOS,
    RECONNAISSANCE,
    ALL_ATTACK_CLASSES,
)
from .config import SEVERITY_MAP
from .correlator import DetectionResult
from .flow import Flow


# ---------------------------------------------------------------------------
# Severity ordering for filtering
# ---------------------------------------------------------------------------
# Numerical weight for each severity label, drawn from SEVERITY_MAP.
# Lower numbers are less severe.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Reverse lookup: severity weight -> human-readable name (for reporting)
WEIGHT_TO_SEVERITY: Dict[int, str] = {v: k for k, v in SEVERITY_WEIGHTS.items()}


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    A single NIDS alert representing a detected security event.

    An Alert is created from a DetectionResult + RiskResult + Flow, and
    carries everything needed for JSON logging, dashboard display, and
    incident response.
    """
    alert_id: str
    timestamp: float
    attack_type: str
    risk_score: float
    severity: str
    confidence: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    triggered_rules: List[str]
    rule_prediction: str
    rule_confidence: float = 0.0
    ml_prediction: str = ""
    ml_confidence: float = 0.0
    explanation: str = ""
    # Extended fields for deduplication tracking
    count: int = 1
    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    suppressed: bool = False

    # Number of duplicate detections suppressed into this alert.
    # count = total observations; suppressed_count = duplicates beyond the first.
    suppressed_count: int = 0

    # Detection-time feature snapshot (the 18 features used for ML inference).
    # None when not available (e.g., alerts created before this field existed).
    feature_snapshot: Optional[List[float]] = None

    # ML top-3 class probabilities: list of (label, probability) tuples.
    # None when not available (e.g., alerts created before this field existed).
    ml_top3: Optional[List[Tuple[str, float]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise this Alert to a plain dictionary suitable for JSON logging.
        """
        return asdict(self)


# ---------------------------------------------------------------------------
# AlertManager configuration
# ---------------------------------------------------------------------------

@dataclass
class AlertManagerConfig:
    """
    Configuration for AlertManager.

    All thresholds are tunable here so that operational parameters can be
    adjusted without code changes.
    """
    # Deduplication window in seconds: identical alerts within this window
    # are collapsed into a single alert with an incremented count.
    dedup_window: float = 30.0

    # Rate limit: maximum alerts per source IP within the dedup window.
    # Once exceeded, new alerts from that source are marked suppressed.
    rate_limit_per_source: int = 10

    # Minimum severity weight to actually emit an alert.
    # INFORMATIONAL=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4.
    # Default: 0 (all severities pass).
    min_severity_weight: int = 0

    # Whether to store suppressed (rate-limited) alerts in the store
    # or discard them entirely.  Keeping them allows dashboard visibility
    # into suppressed volume.
    keep_suppressed: bool = True


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Manages alert creation, deduplication, rate limiting, severity filtering,
    and in-memory storage with thread-safe access.

    Usage:
        manager = AlertManager()
        alert = manager.create_alert(detection_result, risk_result, flow)
    """

    def __init__(self, config: Optional[AlertManagerConfig] = None):
        self.config: AlertManagerConfig = config or AlertManagerConfig()
        self._alerts: List[Alert] = []
        self._lock = threading.Lock()

        # Deduplication state:
        # dedup_key -> {last_seen, count}
        self._dedup_state: Dict[str, Dict[str, Any]] = {}

        # Rate-limit state:
        # source_ip -> count of alerts in current window
        self._rate_limit_state: Dict[str, int] = defaultdict(int)

        # Statistics counters
        self._total_created: int = 0
        self._total_suppressed: int = 0
        self._total_filtered: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_alert(
        self,
        detection_result: DetectionResult,
        risk_result: RiskResult,
        flow: Flow,
        features: Optional[List[float]] = None,
    ) -> Optional[Alert]:
        """
        Create an Alert from the detection pipeline outputs.

        Pipeline:
            1. Check severity filter — return None if below threshold.
            2. Build deterministic dedup key from flow 5-tuple + attack type.
            3. Check dedup state — if a recent identical alert exists,
               increment its count rather than creating a new alert.
            4. Check rate limit for source IP — if exceeded, mark as
               suppressed (if keep_suppressed=True) and return it; otherwise
               return None to indicate the alert was dropped.
            5. Create and store the Alert.

        Args:
            detection_result: The DetectionResult from CorrelationEngine.
            risk_result:      The RiskResult from RiskScorer.
            flow:             The completed Flow that triggered the alert.
            features:         The 18-element feature vector used for ML
                              inference (optional, for investigation display).

        Returns:
            Alert if the alert was created (or re-aggregated), or None
            if the alert was filtered out by severity (not kept in store).
            A suppressed Alert is still returned but has suppressed=True.
        """
        severity = risk_result.severity
        weight = SEVERITY_WEIGHTS.get(severity, 0)

        # --- Step 1: Severity filter ---
        if weight < self.config.min_severity_weight:
            with self._lock:
                self._total_filtered += 1
            return None

        # --- Build alert fields ---
        attack_type = detection_result.final_prediction
        source_ip = flow.src_ip
        destination_ip = flow.dst_ip
        source_port = flow.src_port
        destination_port = flow.dst_port
        protocol = flow.protocol

        # --- Step 2: Dedup key ---
        dedup_key = self._build_dedup_key(
            source_ip, destination_ip, source_port, destination_port, protocol,
            attack_type
        )

        now = time.time()

        with self._lock:
            # --- Step 3: Deduplication ---
            existing = self._dedup_state.get(dedup_key)
            if existing is not None and (now - existing["last_seen"]) < self.config.dedup_window:
                # Collapse into existing alert — find it in the store
                existing_alert = self._find_alert_by_key(dedup_key)
                if existing_alert is not None:
                    existing_alert.count += 1
                    existing_alert.last_seen = now
                    # Preserve combined confidence semantics: keep the higher of
                    # the existing confidence and the new detection's combined
                    # confidence. Do NOT overwrite with RiskResult.confidence,
                    # which is a different quantity than combined_confidence.
                    new_confidence = detection_result.combined_confidence
                    existing_alert.confidence = max(
                        existing_alert.confidence, new_confidence
                    )
                    # Track how many duplicates were suppressed into this alert.
                    # count = total observations; suppressed_count = duplicates beyond the first.
                    existing_alert.suppressed_count += 1

                    # Update the dedup state
                    existing["count"] += 1
                    existing["last_seen"] = now

                    self._total_created += 1
                    return existing_alert

            # --- Step 4: Rate limiting ---
            self._rate_limit_state[source_ip] += 1
            if self._rate_limit_state[source_ip] > self.config.rate_limit_per_source:
                self._total_suppressed += 1
                if not self.config.keep_suppressed:
                    # Reset the counter so it doesn't overflow indefinitely
                    self._rate_limit_state[source_ip] = self._rate_limit_state[source_ip]
                    return None

                # Create a suppressed alert so the dashboard knows
                alert = self._build_alert(
                    detection_result, risk_result, flow, dedup_key, now,
                    suppressed=True, features=features
                )
                alert.explanation = (
                    f"RATE-LIMITED: Source {source_ip} exceeded "
                    f"{self.config.rate_limit_per_source} alerts per "
                    f"{self.config.dedup_window}s window. "
                    f"This detection is recorded but not counted toward normal alert volume. "
                    f"Original: {detection_result.explanation}"
                )
                if self.config.keep_suppressed:
                    self._alerts.append(alert)
                self._total_created += 1
                return alert

            # --- Step 5: Create new alert ---
            # Update dedup state
            self._dedup_state[dedup_key] = {
                "last_seen": now,
                "count": 1,
            }

            alert = self._build_alert(
                detection_result, risk_result, flow, dedup_key, now,
                suppressed=False, features=features
            )
            self._alerts.append(alert)
            self._total_created += 1
            return alert

    def get_all_alerts(self) -> List[Alert]:
        """Return all stored alerts (thread-safe copy)."""
        with self._lock:
            return list(self._alerts)

    def get_recent_alerts(self, n: int = 10) -> List[Alert]:
        """
        Return the N most recent alerts, sorted by timestamp descending.

        Args:
            n: Maximum number of alerts to return.
        """
        with self._lock:
            sorted_alerts = sorted(self._alerts, key=lambda a: a.timestamp, reverse=True)
            return sorted_alerts[:n]

    def count_by_severity(self) -> Dict[str, int]:
        """Return a count of alerts grouped by severity label."""
        with self._lock:
            counts: Dict[str, int] = defaultdict(int)
            for alert in self._alerts:
                counts[alert.severity] += 1
            return dict(counts)

    def count_by_attack_type(self) -> Dict[str, int]:
        """Return a count of alerts grouped by attack_type."""
        with self._lock:
            counts: Dict[str, int] = defaultdict(int)
            for alert in self._alerts:
                counts[alert.attack_type] += 1
            return dict(counts)

    def get_stats(self) -> Dict[str, int]:
        """Return aggregate statistics about the alert manager."""
        with self._lock:
            return {
                "total_alerts": len(self._alerts),
                "total_created": self._total_created,
                "total_suppressed": self._total_suppressed,
                "total_filtered": self._total_filtered,
                "active_dedup_keys": len(self._dedup_state),
                "unique_sources": len(self._rate_limit_state),
            }

    def clear_alerts(self) -> int:
        """
        Remove all stored alerts and reset all state.

        Returns the number of alerts that were cleared.
        """
        with self._lock:
            count = len(self._alerts)
            self._alerts.clear()
            self._dedup_state.clear()
            self._rate_limit_state.clear()
            # Note: total_created / total_suppressed / total_filtered are
            # cumulative statistics and are intentionally NOT reset here.
            # They survive clear() to preserve historical accounting.
            return count

    def prune_old_dedup_state(self, now: Optional[float] = None) -> int:
        """
        Remove dedup state entries that have expired (no activity within
        the dedup window).

        This should be called periodically (e.g., every few minutes) to
        prevent unbounded growth of the dedup state for long-running
        deployments.

        Returns the number of expired entries removed.
        """
        if now is None:
            now = time.time()
        with self._lock:
            expired = [
                key for key, state in self._dedup_state.items()
                if (now - state["last_seen"]) >= self.config.dedup_window
            ]
            for key in expired:
                del self._dedup_state[key]
            return len(expired)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_dedup_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        attack_type: str,
    ) -> str:
        """
        Build a deterministic deduplication key from flow identity + attack type.

        The key captures the essential 'who attacked what' information so that
        repeated detections of the same attack from the same source to the
        same destination within the time window are collapsed.
        """
        return (
            f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:"
            f"proto={protocol}:attack={attack_type}"
        )

    def _find_alert_by_key(self, dedup_key: str) -> Optional[Alert]:
        """
        Find the first stored alert matching a dedup key.

        This is O(n) in the number of alerts.  For production with high
        alert volume, this should be replaced by a dict mapping
        dedup_key -> alert_id.  For the current scope this is sufficient.
        """
        for alert in self._alerts:
            alert_key = self._build_dedup_key(
                alert.source_ip, alert.destination_ip,
                alert.source_port, alert.destination_port,
                alert.protocol, alert.attack_type,
            )
            if alert_key == dedup_key:
                return alert
        return None

    def _build_alert(
        self,
        detection_result: DetectionResult,
        risk_result: RiskResult,
        flow: Flow,
        dedup_key: str,
        now: float,
        suppressed: bool = False,
        features: Optional[List[float]] = None,
    ) -> Alert:
        """
        Construct an Alert object from pipeline outputs.

        Args:
            detection_result: The DetectionResult from CorrelationEngine.
            risk_result:      The RiskResult from RiskScorer.
            flow:             The completed Flow that triggered the alert.
            dedup_key:        The deterministic dedup key.
            now:              Current timestamp.
            suppressed:       Whether this alert is rate-limited.
            features:         The 18-element feature vector (optional).
        """
        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=now,
            attack_type=detection_result.final_prediction,
            risk_score=risk_result.risk_score,
            severity=risk_result.severity,
            confidence=detection_result.combined_confidence,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            source_port=flow.src_port,
            destination_port=flow.dst_port,
            protocol=flow.protocol,
            triggered_rules=list(detection_result.triggered_rules),
            rule_prediction=detection_result.rule_prediction,
            rule_confidence=detection_result.rule_confidence,
            ml_prediction=detection_result.ml_prediction,
            ml_confidence=detection_result.ml_confidence,
            explanation=detection_result.explanation,
            first_seen=now,
            last_seen=now,
            suppressed=suppressed,
            feature_snapshot=list(features) if features is not None else None,
            ml_top3=list(detection_result.ml_top3) if detection_result.ml_top3 else None,
        )


__all__ = [
    "Alert",
    "AlertManager",
    "AlertManagerConfig",
    "SEVERITY_WEIGHTS",
    "WEIGHT_TO_SEVERITY",
]
